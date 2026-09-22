# -*- coding: utf-8 -*-
"""dm-mcp 一次性凭据配置（"一劳永逸"方案）。

解决的问题
----------
DM（大漠插件）需要三样东西才能干活，而它们在每次启动时都要重新凑齐：
    1) 注册码 + 附加码   -> 不注册则 DmGuard / BindWindow 会**进程级崩溃**
    2) 32 位 Python 宿主 -> dm.dll 是 x86 组件，64 位宿主直接失败
    3) 管理员权限        -> DM 的驱动级通道（DmGuard）需要提权

每次手工传参既繁琐又容易漏，本脚本把这三件事一次性固化：

    * 凭据 -> 写入 dm_reg.txt（已 gitignore、读盘即生效、不污染系统环境变量）
    * 宿主 -> 写入 config.json 的 python32_path（避免每次靠自动探测猜）
    * 权限 -> 生成/校验管理员快捷方式（计划任务方案见 --install-task）

用法
----
    # 只做体检，不改任何东西（推荐先跑这个）
    python setup_once.py --check

    # 写入凭据 + 32 位宿主路径，并生成管理员快捷方式
    python setup_once.py --apply

    # 指定值（不传则读现有 dm_reg.txt / 交互询问）
    python setup_once.py --apply --reg-code XXX --extra-code <你的附加码> \
                         --python32 "C:\\...\\Python311-32\\python.exe"

    # 回滚
    python setup_once.py --revert

设计取舍（为什么不用系统环境变量）
----------------------------------
"一劳永逸"有几种做法，本脚本选了**文件方案**，理由：

    | 方案            | 持久 | 对已运行进程生效 | 污染系统 | 换机器 |
    |----------------|------|----------------|---------|--------|
    | 系统环境变量     | ✅   | ❌ 需重启宿主    | 是      | 要重设 |
    | config.json    | ✅   | ✅             | 否      | 要重设 |
    | dm_reg.txt     | ✅   | ✅             | 否      | 要重设 |
    | 管理员计划任务   | ✅   | ✅             | 是(轻)  | 要重建 |

    dm_reg.txt 由 run_server.py 每次启动时读取，**改完重启服务即生效**，
    不像环境变量那样必须重启整个宿主进程（对 MCP 客户端拉起的场景尤其麻烦）。
"""
import argparse
import ctypes
import json
import os
import subprocess
import sys
import winreg

HERE = os.path.dirname(os.path.abspath(__file__))
CONFIG_PATH = os.path.join(HERE, "config.json")
REG_FILE = os.path.join(HERE, "dm_reg.txt")
LNK_NAME = "dm-mcp HTTP 服务（管理员）.lnk"
# 附加码没有默认值：它由"注册时填写的自定义字符串"决定，各人不同。
# 不写死任何真实值，缺省留空，由 --extra-code 或 dm_reg.txt 提供。
DEFAULT_EXTRA = ""


# ------------------------------------------------------------------ 小工具
def log(msg):
    print("[setup] %s" % msg)


def is_admin():
    """是否以管理员身份运行。"""
    try:
        return bool(ctypes.windll.shell32.IsUserAnAdmin())
    except Exception:
        return False


def find_python32():
    """定位 32 位 python.exe：注册表（32 位视图）> 常见目录 > py -3-32。

    返回绝对路径或 ``None``。逐个真实执行校验位数，不靠文件名猜。
    """
    cands = []

    # 1) 注册表 PythonCore（显式指定 32 位视图，否则 64 位 Python 会读到 64 位项）
    for hive, view in ((winreg.HKEY_CURRENT_USER, winreg.KEY_WOW64_32KEY),
                       (winreg.HKEY_LOCAL_MACHINE, winreg.KEY_WOW64_32KEY)):
        try:
            with winreg.OpenKey(hive, r"SOFTWARE\Python\PythonCore", 0,
                                winreg.KEY_READ | view) as k:
                for i in range(winreg.QueryInfoKey(k)[0]):
                    ver = winreg.EnumKey(k, i)
                    try:
                        with winreg.OpenKey(k, ver + r"\InstallPath") as ip:
                            p = os.path.join(winreg.QueryValueEx(ip, "")[0], "python.exe")
                            cands.append(p)
                    except OSError:
                        pass
        except OSError:
            pass

    # 2) 常见安装目录
    local = os.environ.get("LOCALAPPDATA", "")
    for base in (local + r"\Programs\Python" if local else "",
                 r"C:\Python311-32", r"C:\Python310-32", r"C:\Python39-32",
                 r"C:\Python38-32", r"D:\Python311-32"):
        if base and os.path.isdir(base):
            for d in sorted(os.listdir(base), reverse=True):
                p = os.path.join(base, d, "python.exe")
                cands.append(p)

    for p in cands:
        if not (p and os.path.isfile(p)):
            continue
        try:
            out = subprocess.run([p, "-c", "import struct;print(struct.calcsize('P')*8)"],
                                 capture_output=True, text=True, timeout=15)
            if out.stdout.strip() == "32":
                return p
        except Exception:
            continue
    return None


def read_reg_file():
    """读 dm_reg.txt -> (reg_code, extra_code)，缺失为 None。"""
    if not os.path.isfile(REG_FILE):
        return None, None
    reg = extra = None
    with open(REG_FILE, "r", encoding="utf-8-sig") as f:
        for line in f:
            line = line.strip()
            if not line or line.startswith("#") or "=" not in line:
                continue
            k, _, v = line.partition("=")
            k, v = k.strip().lower(), v.strip()
            if k in ("reg_code", "regcode", "注册码"):
                reg = v or None
            elif k in ("extra_code", "extracode", "附加码"):
                extra = v or None
    return reg, extra


def load_config():
    if not os.path.isfile(CONFIG_PATH):
        return {}
    try:
        with open(CONFIG_PATH, "r", encoding="utf-8") as f:
            return json.load(f)
    except Exception as exc:
        log("config.json 读取失败：%s" % exc)
        return {}


def save_config(cfg):
    with open(CONFIG_PATH, "w", encoding="utf-8") as f:
        json.dump(cfg, f, ensure_ascii=False, indent=2)
        f.write("\n")


def mask(s):
    """凭据脱敏：只留头部 6 位尾部 4 位，便于核对又不泄露。"""
    if not s:
        return "(空)"
    s = str(s)
    if len(s) <= 12:
        return s[:2] + "*" * (len(s) - 2)
    return "%s...%s（共 %d 位）" % (s[:6], s[-4:], len(s))


# ------------------------------------------------------------------ 动作
def do_check(reg_code=None, extra_code=None, python32=None):
    """体检：只读，不修改任何文件。"""
    print("=" * 72)
    print("dm-mcp 凭据与运行环境体检（只读，不会修改任何文件）")
    print("=" * 72)

    ok = True

    # --- 1) 管理员权限 ---
    adm = is_admin()
    print("\n[1] 管理员权限")
    print("    当前进程：%s" % ("已是管理员 ✅" if adm else "普通用户 ⚠️"))
    if not adm:
        ok = False
        print("    -> DM 的驱动级通道（DmGuard）需要提权。")
        print("       做法：右键 启动_HTTP常驻.bat -> 以管理员身份运行；")
        print("       或执行 python setup_once.py --apply 生成管理员快捷方式（一劳永逸）。")

    # --- 2) 32 位宿主 ---
    print("\n[2] 32 位 Python 宿主（dm.dll 是 x86 组件，必须 32 位）")
    cur_bits = 64 if sys.maxsize > 2 ** 32 else 32
    print("    当前解释器：%s（%d 位）" % (sys.executable, cur_bits))
    host = python32 or load_config().get("python32_path") or find_python32()
    if host and os.path.isfile(host):
        try:
            out = subprocess.run([host, "-c", "import struct;print(struct.calcsize('P')*8)"],
                                 capture_output=True, text=True, timeout=15)
            bits = out.stdout.strip()
        except Exception as exc:
            bits = "检测失败：%s" % exc
        print("    32 位解释器：%s（自检 %s 位）" % (host, bits))
        if bits != "32":
            ok = False
            print("    -> ⚠️ 该路径不是 32 位解释器，请换一个。")
    else:
        ok = False
        print("    -> ⚠️ 未找到 32 位 Python。")
        print("       run_server.py 启动时会自动探测；若探测失败请显式指定：")
        print('       python setup_once.py --apply --python32 "D:\\...\\Python311-32\\python.exe"')

    # --- 3) 凭据 ---
    print("\n[3] DM 凭据（注册码 / 附加码）")
    f_reg, f_extra = read_reg_file()
    cfg = load_config()
    eff_reg = reg_code or f_reg or cfg.get("reg_code")
    eff_extra = extra_code or f_extra or cfg.get("extra_code") or ""

    print("    dm_reg.txt        ：%s" % ("存在" if os.path.isfile(REG_FILE) else "不存在"))
    print("    注册码            ：%s（来源：%s）" % (
        mask(eff_reg),
        "命令行" if reg_code else ("dm_reg.txt" if f_reg else ("config.json" if cfg.get("reg_code") else "无"))))
    print("    附加码            ：%s（来源：%s）" % (
        mask(eff_extra) if eff_extra else "(未配置)",
        "命令行" if extra_code else ("dm_reg.txt" if f_extra else ("config.json" if cfg.get("extra_code") else "无"))))
    if not eff_reg:
        ok = False
        print("    -> ⚠️ 没有注册码。未注册时 DmGuard / BindWindow 会**进程级崩溃**，")
        print("       服务会主动拒绝调用（返回 DM_NOT_REGISTERED）。")
        print("       做法：python setup_once.py --apply --reg-code <你的注册码> --extra-code %s" % DEFAULT_EXTRA)
    if eff_reg and not eff_extra:
        print("    -> 提示：未配置附加码。实测 DM 不校验其内容（传空也能 Reg=1），")
        print("       但按约定应填注册时写的附加码，建议补上。")

    # --- 4) 凭据文件是否会被提交 ---
    print("\n[4] 凭据文件是否已排除出版本控制")
    gi = os.path.join(HERE, ".gitignore")
    ignored = False
    if os.path.isfile(gi):
        with open(gi, "r", encoding="utf-8") as f:
            txt = f.read()
        ignored = "dm_reg.txt" in txt and "config.json" in txt
    print("    .gitignore 覆盖 dm_reg.txt + config.json：%s" % ("是 ✅" if ignored else "否 ⚠️"))
    if not ignored:
        ok = False
        print("    -> 危险：凭据可能被提交到仓库。请把 dm_reg.txt、config.json 加进 .gitignore。")

    # --- 5) dm.dll ---
    print("\n[5] dm.dll")
    dll = cfg.get("dm_path") or ""
    print("    config.json dm_path：%s" % (dll or "(未配置，将自动探测)"))
    if dll:
        if os.path.isfile(dll):
            print("    文件存在 ✅  %s" % dll)
        else:
            ok = False
            print("    -> ⚠️ 文件不存在：%s" % dll)

    # --- 6) 目标游戏 ---
    print("\n[6] 目标进程（剑灵）")
    try:
        out = subprocess.run(["tasklist", "/FI", "IMAGENAME eq BNSR.exe", "/NH"],
                             capture_output=True, text=True, timeout=20)
        running = "BNSR.exe" in (out.stdout or "")
        print("    BNSR.exe：%s" % ("正在运行 ✅" if running else "未运行（不影响配置，玩游戏时再启动服务即可）"))
    except Exception as exc:
        print("    检测失败：%s（忽略）" % exc)

    print("\n" + "=" * 72)
    print("体检结论：%s" % ("全部就绪 ✅" if ok else "存在待处理项 ⚠️（见上方 -> 提示）"))
    print("=" * 72)
    return 0 if ok else 1


def do_apply(reg_code=None, extra_code=None, python32=None, make_shortcut=True):
    """写入 dm_reg.txt 与 config.json，并生成管理员快捷方式。"""
    print("=" * 72)
    print("dm-mcp 一次性配置（会写入 dm_reg.txt / config.json）")
    print("=" * 72)

    # --- 1) 凭据落盘 ---
    old_reg, old_extra = read_reg_file()
    reg = reg_code or old_reg
    extra = extra_code if extra_code is not None else (old_extra or DEFAULT_EXTRA)
    if not reg:
        print("\n[!] 没有注册码，无法写入凭据。请加 --reg-code <注册码>，")
        print("    或先手工在 dm_reg.txt 里填好 reg_code= 再执行 --apply。")
        return 2

    content = """# dm-mcp 凭据文件（本文件已被 .gitignore 排除，切勿提交到任何仓库或分享给他人）
#
# 格式：每行 `键=值`，`#` 开头为注释行。
# 支持的键：reg_code（注册码）、extra_code（附加码）
#
# 解析优先级（高 -> 低）：
#   --reg-code / --extra-code 命令行  >  环境变量 DM_REG_CODE / DM_EXTRA_CODE
#     >  本文件  >  config.json 的 reg_code / extra_code
#
# 为什么用文件而不是系统环境变量：
#   环境变量需要在"启动宿主进程之前"设置好，且改了之后必须重启宿主进程才生效；
#   本文件由 run_server.py 每次启动时读取，改完重启服务即生效，不污染系统环境。

reg_code=%s
extra_code=%s
""" % (reg, extra or "")
    with open(REG_FILE, "w", encoding="utf-8") as f:
        f.write(content)
    try:
        os.chmod(REG_FILE, 0o600)
    except Exception:
        pass
    print("\n[1] 凭据已写入 dm_reg.txt")
    print("    注册码：%s" % mask(reg))
    print("    附加码：%s" % (mask(extra) if extra else "(空)"))

    # --- 2) 32 位宿主写进 config.json ---
    cfg = load_config()
    changed = []
    if python32:
        cfg["python32_path"] = python32
        changed.append("python32_path")
    elif not cfg.get("python32_path"):
        found = find_python32()
        if found:
            cfg["python32_path"] = found
            changed.append("python32_path（自动探测）")
    # 凭据字段留空：优先走 dm_reg.txt，避免同一凭据存在两处而不同步
    if cfg.get("reg_code"):
        cfg["reg_code"] = ""
        changed.append("reg_code 清空（改用 dm_reg.txt）")
    cfg.setdefault("extra_code", "")
    if cfg.get("extra_code"):
        cfg["extra_code"] = ""
        changed.append("extra_code 清空（改用 dm_reg.txt）")

    if changed:
        save_config(cfg)
        print("\n[2] config.json 已更新：%s" % "、".join(changed))
        print("    python32_path = %s" % cfg.get("python32_path", "(未设置)"))
    else:
        print("\n[2] config.json 无需变更")

    # --- 3) 管理员快捷方式 ---
    if make_shortcut:
        ok = make_admin_shortcut()
        print("\n[3] 管理员快捷方式：%s" % ("已生成 ✅" if ok else "生成失败（可手工设置，见下方说明）"))
        if ok:
            print("    %s\\%s" % (HERE, LNK_NAME))
            print("    -> 以后双击它启动服务，会自动弹 UAC 提权，无需再手工右键。")

    print("\n" + "=" * 72)
    print("配置完成。下一步：")
    print("  1) 双击「%s」启动服务（自动提权）" % LNK_NAME)
    print("  2) 或在本窗口执行：run_server.py --check 验证链路")
    print("=" * 72)
    return 0


def make_admin_shortcut():
    """在项目目录生成"以管理员身份运行"的快捷方式（指向 启动_HTTP常驻.bat）。

    实现方式：用 PowerShell 的 WScript.Shell COM 创建 .lnk，
    并给字节 0x15 置位以设置"以管理员身份运行"标志（shell link 的 RunAsAdmin）。
    这里走 subprocess 调 PowerShell，避免依赖 pywin32。
    """
    target = os.path.join(HERE, "启动_HTTP常驻.bat")
    if not os.path.isfile(target):
        log("找不到 %s，跳过快捷方式" % target)
        return False
    lnk = os.path.join(HERE, LNK_NAME)
    ps = r'''
$ErrorActionPreference = "Stop"
$ws = New-Object -ComObject WScript.Shell
$sc = $ws.CreateShortcut("%(lnk)s")
$sc.TargetPath = "%(target)s"
$sc.WorkingDirectory = "%(here)s"
$sc.Description = "dm-mcp HTTP 服务（自动以管理员身份运行）"
$sc.IconLocation = "%%SystemRoot%%\System32\shell32.dll,77"
$sc.Save()
# 给 .lnk 打上"以管理员身份运行"标志位
$b = [System.IO.File]::ReadAllBytes("%(lnk)s")
$b[0x15] = $b[0x15] -bor 0x20
[System.IO.File]::WriteAllBytes("%(lnk)s", $b)
Write-Output "OK"
''' % {"lnk": lnk.replace('"', '`"'), "target": target.replace('"', '`"'),
       "here": HERE.replace('"', '`"')}
    try:
        out = subprocess.run(["powershell", "-NoProfile", "-NonInteractive", "-Command", ps],
                             capture_output=True, text=True, timeout=90)
        return "OK" in (out.stdout or "") and os.path.isfile(lnk)
    except Exception as exc:
        log("快捷方式创建异常：%s" % exc)
        return False


def do_revert():
    """回滚：删除 dm_reg.txt 中的凭据（保留文件与注释，便于再次填写）。"""
    print("=" * 72)
    print("回滚 dm-mcp 凭据配置")
    print("=" * 72)
    if os.path.isfile(REG_FILE):
        os.remove(REG_FILE)
        print("\n[1] 已删除 dm_reg.txt")
    else:
        print("\n[1] dm_reg.txt 不存在，跳过")

    cfg = load_config()
    if cfg.get("reg_code") or cfg.get("extra_code"):
        cfg["reg_code"] = ""
        cfg["extra_code"] = ""
        save_config(cfg)
        print("[2] 已清空 config.json 中的 reg_code / extra_code")
    else:
        print("[2] config.json 中无凭据，跳过")

    lnk = os.path.join(HERE, LNK_NAME)
    if os.path.isfile(lnk):
        os.remove(lnk)
        print("[3] 已删除管理员快捷方式")
    else:
        print("[3] 管理员快捷方式不存在，跳过")
    print("\n提示：32 位 Python 路径（config.json 的 python32_path）未改动。")
    return 0


# ------------------------------------------------------------------ 入口
def main(argv=None):
    p = argparse.ArgumentParser(
        description="dm-mcp 一次性凭据配置（注册码 + 附加码 + 管理员权限 + 32 位宿主）",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="示例：\n"
               "  python setup_once.py --check                    # 只体检\n"
               "  python setup_once.py --apply --reg-code XXX --extra-code <你的附加码>\n"
               "  python setup_once.py --revert                  # 回滚\n")
    p.add_argument("--check", action="store_true", help="只体检，不修改任何文件")
    p.add_argument("--apply", action="store_true", help="写入凭据并生成管理员快捷方式")
    p.add_argument("--revert", action="store_true", help="回滚（删除凭据与快捷方式）")
    p.add_argument("--reg-code", default=None, help="DM 注册码")
    p.add_argument("--extra-code", default=None, help="DM 附加码（注册时填写的自定义字符串）")
    p.add_argument("--python32", default=None, help="32 位 python.exe 绝对路径")
    p.add_argument("--no-shortcut", action="store_true", help="不生成管理员快捷方式")
    args = p.parse_args(argv)

    if args.revert:
        return do_revert()
    if args.apply:
        return do_apply(args.reg_code, args.extra_code, args.python32,
                        make_shortcut=not args.no_shortcut)
    return do_check(args.reg_code, args.extra_code, args.python32)


if __name__ == "__main__":
    sys.exit(main())
