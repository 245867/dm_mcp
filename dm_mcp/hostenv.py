# -*- coding: utf-8 -*-
"""32 位宿主自举（bitness bootstrap）。

背景：dm.dll 是 x86（32 位）组件，且 DM 通过内核级 DmGuard 访问 64 位目标进程。
因此 dm-mcp 的宿主解释器必须是 **32 位**：64 位进程既无法 ``CoCreateInstance``
32 位 in-proc COM 对象（ProgID ``dm.dmsoft``，表现为创建失败/返回 None/HRESULT 报错），
也无法 ``LoadLibrary`` 加载 x86 的 dm.dll。

本模块负责（启动时由 run_server.py 首先调用）：

    1) 探测本机可用的 32 位 Python 解释器：
       显式参数 → config.json.python32_path → 环境变量 → 项目内目录 →
       注册表 PythonCore（32 位视图）→ 常见安装目录 → Python 启动器 ``py -3-32``；
       每个候选都会真实执行一次 ``-c "…sizeof(c_void_p)…"`` 校验位数（不猜）。
    2) 当前宿主为 64 位时，自动用找到的 32 位解释器 **重新拉起自身**
       （子进程继承 stdin/stdout/stderr，MCP stdio 管道不被打断）。
    3) 找不到 32 位解释器时，给出可操作的引导报错（含获取与配置步骤），进程以码 2 退出。

重入保护：重拉时设置环境变量 ``DM_MCP_RELAUNCHED=1``；若再次进入仍是 64 位，则不再重拉，
直接引导报错，避免无限自我拉起。
"""

import glob
import os
import subprocess
import sys

from . import errors as E

PROBE_CODE = "import ctypes,sys;sys.stdout.write(str(ctypes.sizeof(ctypes.c_void_p)*8))"
PROBE_TIMEOUT = 20
_CREATE_NO_WINDOW = 0x08000000
_MAX_TRIED_REPORT = 12
RELAUNCH_ENV = "DM_MCP_RELAUNCHED"
PYTHON32_ENV = "DM_MCP_PYTHON32"


# ---------------------------------------------------------------- 基础探测
def is_32bit_process():
    """当前进程的解释器是否为 32 位。"""
    import ctypes
    return ctypes.sizeof(ctypes.c_void_p) == 4


def current_host():
    """当前宿主描述（用于日志 / dm_status）。"""
    return {
        "exe": sys.executable,
        "python": sys.version.split()[0],
        "bits": 32 if is_32bit_process() else 64,
        "relaunched": os.environ.get(RELAUNCH_ENV) == "1",
    }


def host_report_line():
    h = current_host()
    return "宿主：%s（Python %s，%d 位%s）" % (
        h["exe"], h["python"], h["bits"], "，由 64 位自动重拉" if h["relaunched"] else "")


def _key(exe):
    exe = (exe or "").strip()
    if len(exe) > 2 and exe[1] == ":":
        return os.path.normcase(os.path.abspath(os.path.expandvars(exe)))
    return os.path.normcase(exe)


def _project_root():
    return os.path.dirname(os.path.dirname(os.path.abspath(__file__)))


def probe_python(exe, timeout=PROBE_TIMEOUT):
    """真实执行候选解释器，校验其位数。返回 {exe, ok, bits, error, source}。"""
    info = {"exe": exe, "ok": False, "bits": None, "error": None, "source": None}
    exe = (exe or "").strip()
    if not exe:
        info["error"] = "空路径"
        return info
    if os.path.isfile(exe):
        cmd = [exe, "-c", PROBE_CODE]
    elif len(exe) > 2 and exe[1] == ":":
        info["error"] = "文件不存在"
        return info
    else:
        cmd = exe.split() + ["-c", PROBE_CODE]  # 形如 "py -3-32"
    kw = {}
    if os.name == "nt":
        kw["creationflags"] = _CREATE_NO_WINDOW
    try:
        raw = subprocess.check_output(cmd, stderr=subprocess.STDOUT, timeout=timeout, **kw)
        text = raw.decode("ascii", "ignore").strip()
        info["bits"] = int(text) if text else None
    except Exception as exc:  # FileNotFoundError / CalledProcessError / TimeoutExpired ...
        info["error"] = "%s: %s" % (type(exc).__name__, str(exc)[:120])
        return info
    info["ok"] = info["bits"] == 32
    if not info["ok"]:
        info["error"] = "探测到 %s 位" % info["bits"]
    return info


# ---------------------------------------------------------------- 候选来源
def _project_candidates(root):
    return [
        os.path.join(root, "python32", "python.exe"),
        os.path.join(root, "python32-embed", "python.exe"),
        os.path.join(root, "runtime32", "python.exe"),
        os.path.join(root, "venv32", "Scripts", "python.exe"),
        os.path.join(root, ".venv32", "Scripts", "python.exe"),
        os.path.join(root, "..", "python32", "python.exe"),
    ]


def _registry_candidates():
    """从注册表的 32 位视图反查已安装的 Python（最可靠，不受安装盘符影响）。"""
    out = []
    try:
        import winreg
    except ImportError:
        return out
    views = [(winreg.HKEY_LOCAL_MACHINE, r"SOFTWARE\Python\PythonCore"),
             (winreg.HKEY_CURRENT_USER, r"SOFTWARE\Python\PythonCore")]
    for hive, sub in views:
        for base in (sub, sub.replace("SOFTWARE\\", "SOFTWARE\\WOW6432Node\\", 1)):
            try:
                with winreg.OpenKey(hive, base, 0, winreg.KEY_READ | winreg.KEY_WOW64_32KEY) as k:
                    count = winreg.QueryInfoKey(k)[0]
                    tags = [winreg.EnumKey(k, i) for i in range(count)]
            except OSError:
                continue
            for tag in tags:
                try:
                    with winreg.OpenKey(hive, base + "\\" + tag + r"\InstallPath", 0,
                                        winreg.KEY_READ | winreg.KEY_WOW64_32KEY) as ip:
                        try:
                            exe = winreg.QueryValueEx(ip, "ExecutablePath")[0]
                        except OSError:
                            exe = os.path.join(winreg.QueryValueEx(ip, "")[0], "python.exe")
                    if exe:
                        out.append(exe)
                except OSError:
                    continue
    return out


def _glob_candidates():
    home = os.environ.get("USERPROFILE") or r"C:\Users\Default"
    local = os.environ.get("LOCALAPPDATA") or os.path.join(home, "AppData", "Local")
    patterns = [
        r"C:\Python3*-32\python.exe",
        r"C:\Python3*\python.exe",
        r"C:\Python32\python.exe",
        os.path.join(local, "Programs", "Python", "Python3*-32", "python.exe"),
        os.path.join(local, "Programs", "Python", "Python3*", "python.exe"),
        r"D:\Python3*-32\python.exe",
        r"D:\Python3*\python.exe",
        r"D:\Python32\python.exe",
        r"D:\Develop\Python3*-32\python.exe",
        r"D:\Soft\Python3*-32\python.exe",
        r"D:\Tools\Python3*-32\python.exe",
        r"D:\Program Files (x86)\Python3*\python.exe",
        r"E:\Python3*-32\python.exe",
    ]
    for pf in (os.environ.get("ProgramFiles(x86)"), r"C:\Program Files (x86)"):
        if pf:
            patterns.append(os.path.join(pf, "Python3*", "python.exe"))
    out = []
    for p in patterns:
        try:
            out.extend(sorted(glob.glob(p)))
        except Exception:
            continue
    return out


def python32_candidates(cfg=None, explicit=None):
    """返回 32 位解释器候选列表 [(exe, 来源说明)]，按优先级排序并去重。"""
    cfg = cfg or {}
    root = _project_root()
    out = []
    if explicit:
        out.append((explicit, "--python32 参数"))
    p = cfg.get("python32_path")
    if p:
        out.append((p, "config.json: python32_path"))
    for env in (PYTHON32_ENV, "DM_PYTHON32"):
        v = os.environ.get(env)
        if v:
            out.append((v, "环境变量 %s" % env))
    for p in _project_candidates(root):
        out.append((p, "项目内目录（如 python32\\python.exe）"))
    for p in _registry_candidates():
        out.append((p, "注册表 PythonCore（32 位视图）"))
    for p in _glob_candidates():
        out.append((p, "常见安装目录"))
    for cmd in ("py -3-32", "py -3.12-32", "py -3.11-32", "py -3.10-32"):
        out.append((cmd, "Python 启动器 %s" % cmd))
    seen, uniq = set(), []
    for exe, src in out:
        k = _key(exe)
        if not k or k in seen:
            continue
        seen.add(k)
        uniq.append((exe, src))
    return uniq


def find_python32(cfg=None, explicit=None, log=None):
    """探测并返回第一个真正可用的 32 位解释器。返回 (exe|None, source|None, tried[])。"""
    tried = []
    for exe, src in python32_candidates(cfg, explicit):
        info = probe_python(exe)
        info["source"] = src
        tried.append(info)
        if log:
            log("32 位解释器探测：%s（%s）-> %s" % (exe, src, "OK" if info["ok"] else info["error"]))
        if info["ok"]:
            return exe, src, tried
    return None, None, tried


# ---------------------------------------------------------------- 重拉自身
def relaunch(pyexe, script, argv=None):
    """用 32 位解释器重新拉起 ``script``，继承 stdio（MCP stdio 管道可用）。返回 (返回码, 命令行)。"""
    env = os.environ.copy()
    env[RELAUNCH_ENV] = "1"
    env[PYTHON32_ENV] = pyexe
    head = [pyexe] if os.path.isfile(pyexe) else pyexe.split()
    cmd = head + [script] + list(argv or [])
    proc = subprocess.run(cmd, env=env)
    return (proc.returncode if proc.returncode is not None else 0), cmd


# ---------------------------------------------------------------- 引导文案
def build_guide_text(script, cfg=None, tried=None, relaunched=False, reason=None, code=None):
    code = code or E.NO_PYTHON32
    lines = []
    lines.append("")
    lines.append("=" * 78)
    lines.append("dm-mcp 启动中止：宿主位数不合格（当前为 64 位，必须是 32 位）")
    lines.append("错误码：%s（%s）" % (code, E.MESSAGES.get(code, code)))
    lines.append("=" * 78)
    lines.append("原因：dm.dll 是 32 位（x86）组件，且 DM 依赖内核级 DmGuard 访问 64 位目标进程。")
    lines.append("      64 位进程创建 dm.dmsoft COM 对象必然失败（表现为“COM 后端不可用/返回 None”）。")
    lines.append("当前解释器：%s（%d 位）" % (sys.executable, 32 if is_32bit_process() else 64))
    if reason:
        lines.append("说明：%s" % reason)
    lines.append("")
    lines.append("获取并配置 32 位 Python（任选一种）：")
    lines.append("  A. 官方安装包（推荐，最省事）")
    lines.append("     1) 打开 https://www.python.org/downloads/windows/")
    lines.append("     2) 下载 “Windows installer (32-bit)”（文件名形如 python-3.11.9.exe，勿选 x86-64）")
    lines.append("     3) 安装时勾选 “Add python.exe to PATH”，也可自定义安装到 D:\\Python311-32")
    lines.append("  B. winget 一行安装（Windows 10/11 自带）")
    lines.append("     winget install --id Python.Python.3.11 --architecture x86 -e")
    lines.append("  C. 免安装嵌入式包（不写注册表、不污染 PATH）")
    lines.append("     下载 “Windows embeddable package (32-bit)”，解压到：")
    lines.append("     %s" % os.path.join(_project_root(), "python32") + "\\")
    lines.append("     （该目录下应能看到 python.exe）")
    lines.append("")
    lines.append("配置给 dm-mcp（任选一种，优先级从高到低）：")
    lines.append("  1) 启动参数：    python run_server.py --mode http --python32 \"D:\\Python311-32\\python.exe\"")
    lines.append("  2) config.json： {\"python32_path\": \"D:\\\\Python311-32\\\\python.exe\"}")
    lines.append("  3) 环境变量：    set DM_MCP_PYTHON32=D:\\Python311-32\\python.exe")
    lines.append("  4) 项目内目录：  把 32 位解释器放到 %s"
                 % os.path.join(_project_root(), "python32", "python.exe"))
    lines.append("")
    lines.append("配置完成后直接重新启动 %s 即可：")
    lines.append("启动时会自动检测宿主位数，若为 64 位则改用 32 位解释器重新拉起自身。")
    lines.append("（如需在 64 位下仅查看引导信息，可加 --no-relaunch 跳过自动重拉。）")
    script = os.path.abspath(script)
    lines.append("")
    lines.append("入口脚本：%s" % script)
    if tried:
        lines.append("已尝试的候选解释器（最多列出 %d 条）：" % _MAX_TRIED_REPORT)
        for info in tried[:_MAX_TRIED_REPORT]:
            lines.append("    %-58s %s" % (info.get("exe"), info.get("error") or "OK"))
        if len(tried) > _MAX_TRIED_REPORT:
            lines.append("    ……其余 %d 条略" % (len(tried) - _MAX_TRIED_REPORT))
    else:
        lines.append("未执行候选探测（自动重拉被关闭或已重拉过一次）。")
    lines.append("=" * 78)
    lines.append("")
    return "\n".join(lines) + "\n"


# ---------------------------------------------------------------- 对外入口
def ensure_32bit_host(script, argv=None, cfg=None, explicit_python32=None,
                      auto_relaunch=True, stream=None, log=None):
    """启动自检：确保以 32 位宿主运行。

    - 已是 32 位：直接返回 {"mode": "native", ...}
    - 是 64 位且找到 32 位解释器：用其重新拉起本脚本，父进程 sys.exit(子进程返回码)
    - 找不到：打印引导文案后 sys.exit(2)
    """
    script = os.path.abspath(script)
    stream = stream or sys.stderr
    if is_32bit_process():
        if log:
            log(host_report_line())
        return {"mode": "native", "bits": 32, "exe": sys.executable}

    if log:
        log("宿主位数不合格：%s（64 位），dm.dll 为 x86 组件" % sys.executable)

    relaunched = os.environ.get(RELAUNCH_ENV) == "1"
    if auto_relaunch and not relaunched:
        exe, src, tried = find_python32(cfg, explicit_python32, log=log)
        if exe:
            msg = "检测到 64 位宿主，已自动改用 32 位解释器重新拉起自身：%s（来源：%s）" % (exe, src)
            stream.write(msg + "\n")
            stream.flush()
            if log:
                log(msg)
            try:
                code, cmd = relaunch(exe, script, argv)
            except Exception as exc:  # 32 位解释器存在但拉起失败（权限 / 路径 / 被杀软拦截等）
                stream.write(build_guide_text(
                    script, cfg, tried, relaunched=relaunched,
                    reason="%s：已找到 32 位解释器 %s（来源：%s），但重新拉起自身失败（%s: %s）"
                           % (E.RELAUNCH_FAILED, exe, src, type(exc).__name__, str(exc)[:120]),
                    code=E.RELAUNCH_FAILED))
                stream.flush()
                if log:
                    log("重新拉起失败：%s" % exc)
                sys.exit(2)
            if log:
                log("32 位宿主已退出，返回码=%s；命令行=%s" % (code, " ".join(cmd)))
            sys.exit(code)

    if not auto_relaunch or relaunched:
        tried = []
        reason = ("已按 %s=1 跳过自动重拉（但仍为 64 位，可能是配置的 python32_path 指向了 64 位解释器）"
                  % RELAUNCH_ENV) if relaunched else "自动重拉已关闭（--no-relaunch）"
    else:
        reason = "未找到任何可用的 32 位 Python 解释器"
    code = E.RELAUNCH_FAILED if relaunched else E.NO_PYTHON32
    stream.write(build_guide_text(script, cfg, tried, relaunched=relaunched, reason=reason, code=code))
    stream.flush()
    sys.exit(2)
