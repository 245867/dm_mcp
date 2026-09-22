# -*- coding: utf-8 -*-
"""dm-mcp 统一入口（32 位宿主自举 + 启动默认绑定《剑灵》）。

用法示例：
    # 1) 自检（加载 dm.dll -> Reg -> 加载盾 -> 找窗口 -> 绑定 -> 读模块基址 MZ 头）
    python run_server.py --check

    # 2) 自检并附带真实写测试（只写服务自己申请的临时内存，默认关闭）
    python run_server.py --check --allow-write

    # 3) 常驻 HTTP 服务（127.0.0.1:27043，MCP 走 POST /mcp，REST 走 /api/<tool>）
    python run_server.py --mode http --port 27043

    # 4) MCP stdio 服务（供 MCP 客户端拉起）
    python run_server.py --mode stdio

32 位宿主（启动自检，第一优先级）：
    dm.dll 是 32 位（x86）组件，DM 又依赖内核级 DmGuard 访问 64 位目标进程，因此本服务
    **必须**以 32 位 Python 运行 —— 64 位进程创建 dm.dmsoft COM 对象必然失败（返回 None /
    HRESULT 报错），也无法 LoadLibrary 加载 x86 的 dm.dll。
    本入口启动时先做宿主位数自检（实现见 dm_mcp/hostenv.py）：
        * 已是 32 位 -> 直接继续启动；
        * 是 64 位且有 32 位解释器 -> 自动用其“重新拉起自身”（stdio 管道继承，MCP 客户端无感）；
        * 找不到 32 位解释器 -> 打印“获取 / 配置 32 位 Python”的引导文案后退出（返回码 2）。
    32 位解释器来源优先级（逐个真实执行校验位数，不猜）：
        --python32 > config.json 的 python32_path > 环境变量 DM_MCP_PYTHON32 >
        项目内 python32\\python.exe 等目录 > 注册表 PythonCore(32 位视图) >
        常见安装目录（C:\\Python3*-32、%LOCALAPPDATA%\\Programs\\Python\\Python3*-32、D:\\ 等）> py -3-32

启动流程（固定三步，每步单独打日志）：
    ① 创建 DM 对象  -> ② Reg 注册  -> ③ 绑定窗口
    第 ③ 步分两条路：

    * **传了 hwnd（推荐）**：`--hwnd 0x1102B2` 或 ``config.json`` 的 ``"hwnd"``。
      严格绑定该句柄，**完全不做窗口查找、也不做类名/标题复核**。
      为什么推荐：自动查找要依次尝试 FindWindow / FindWindowByProcess / 纯标题 /
      纯类名六种候选，实测存在第三方工具持有标题含"剑灵"的窗口，误绑后
      读到的是垃圾数据且极难排查；而调用方本来就知道要绑哪个窗口。
    * **没传 hwnd**：退回 `dm_auto_bind` 的自动查找（见下），保留"游戏后启动也能自动接上"的便利。

    hwnd 在 64 位 -> 32 位自举时会随 argv 一起传递，客户端无感。

自动查找（仅在未传 hwnd 且 ``auto_bind`` 为真时执行）：
    依次尝试 class=UnrealWindow / 标题含"剑灵" / 进程 bnsr.exe 的六种候选组合，
    命中后**逐个复核类名与标题**；结果写入 dm_status 的 auto_bind 字段。
    游戏未启动时不影响服务启动，可稍后调用 dm_auto_bind 重试，或用 --no-autobind 关闭。

配置文件 config.json（与 run_server.py 同目录，可选）：
    {"dm_path": "D:\\dm\\dm.dll", "reg_code": "xxxx", "guard_modes": ["memory2","b3"],
     "asm_timeout_ms": 10000, "http_port": 27043, "window_class": "UnrealWindow",
     "window_title": "剑灵", "module": "bnsr.exe", "hwnd": "0x1102B2",
     "python32_path": "D:\\Python311-32\\python.exe", "auto_bind": true}
"""
import argparse
import json
import os
import sys
import time

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from dm_mcp import DEFAULT_HTTP_PORT, __version__          # noqa: E402
from dm_mcp import errors as E                              # noqa: E402
from dm_mcp import hostenv as HOST                          # noqa: E402
from dm_mcp import server as SRV                            # noqa: E402
from dm_mcp.core import DmCore                              # noqa: E402

CONFIG_PATH = os.path.join(os.path.dirname(os.path.abspath(__file__)), "config.json")
ENTRY_SCRIPT = os.path.abspath(__file__)


def load_config():
    """读取 config.json；失败返回空 dict（不阻断启动）。

    对以 ``_`` 开头的键做剔除：config.json / config.example.json 用它们写“字段说明”，
    不属于真实配置，避免被后续 ``cfg.get(...)`` 误读。
    """
    if not os.path.isfile(CONFIG_PATH):
        return {}
    try:
        with open(CONFIG_PATH, "r", encoding="utf-8") as f:
            raw = json.load(f)
    except Exception as exc:
        SRV.log("config.json 解析失败：%s" % exc)
        return {}
    if not isinstance(raw, dict):
        SRV.log("config.json 顶层必须是 JSON 对象，已忽略")
        return {}
    return {k: v for k, v in raw.items() if not str(k).startswith("_")}


REG_FILE = os.path.join(os.path.dirname(os.path.abspath(__file__)), "dm_reg.txt")


def _read_reg_file():
    """读取 dm_reg.txt（凭据落盘文件）。返回 ``(reg_code, extra_code)``，缺失为 ``None``。

    文件格式（每行 ``键=值``，``#`` 开头为注释；也兼容"只有一行注册码"的裸格式）::

        # dm-mcp 凭据文件（已被 .gitignore 排除，切勿提交）
        reg_code=<你的注册码>
        extra_code=<你的附加码>

    为什么提供文件方式而不是只靠环境变量：
        环境变量在 Windows 上分"用户级/系统级"，且对**已启动的其他程序无效**
        （需要重启宿主进程才会继承）。文件方式读盘即生效，重启服务即可，
        配合 `安装_凭据与权限.bat` 可以做到"设一次，长期有效"。

    Returns:
        ``(reg_code, extra_code)``，任一未配置则为 ``None``。
    """
    if not os.path.isfile(REG_FILE):
        return None, None
    reg_code = extra_code = None
    try:
        with open(REG_FILE, "r", encoding="utf-8-sig") as f:
            for line in f:
                line = line.strip()
                if not line or line.startswith("#"):
                    continue
                if "=" not in line:
                    # 裸格式：整行当注册码（便于用户直接粘贴注册码）
                    if reg_code is None and len(line) >= 16:
                        reg_code = line
                    continue
                k, _, v = line.partition("=")
                k, v = k.strip().lower(), v.strip()
                if k in ("reg_code", "regcode", "注册码"):
                    reg_code = v or None
                elif k in ("extra_code", "extracode", "附加码"):
                    extra_code = v or None
    except Exception as exc:
        SRV.log("dm_reg.txt 解析失败：%s" % exc)
        return None, None
    return reg_code, extra_code


def resolve_credentials(cli_reg, cli_extra, cfg):
    """解析注册码 + 附加码（优先级：命令行 > 环境变量 > dm_reg.txt > config.json）。

    注册码属敏感凭据：命令行会留在进程列表和 shell 历史里，
    config.json 会明文落盘进项目目录，因此**推荐 dm_reg.txt 或环境变量**：
        * dm_reg.txt —— 已 gitignore、读盘即生效、不动系统环境（推荐）
        * 环境变量   —— 不落盘，但需要重启宿主进程才能被继承

    Returns:
        ``(reg_code, extra_code, source_desc)``。
    """
    if cli_reg:
        return cli_reg, cli_extra or "", "--reg-code 参数"
    for env in ("DM_REG_CODE", "DM_MCP_REG_CODE"):
        v = os.environ.get(env)
        if v:
            extra = os.environ.get("DM_EXTRA_CODE") or os.environ.get("DM_MCP_EXTRA_CODE") or cli_extra or ""
            return v, extra, "环境变量 %s" % env
    f_reg, f_extra = _read_reg_file()
    if f_reg:
        return f_reg, (cli_extra or f_extra or ""), "dm_reg.txt"
    v = cfg.get("reg_code")
    if v:
        return v, str(cfg.get("extra_code") or cli_extra or ""), "config.json: reg_code（明文落盘，建议改用 dm_reg.txt）"
    return None, (cli_extra or ""), None


def resolve_reg_code(cli_value, cfg):
    """注册码解析（向后兼容旧调用点）。

    优先级：命令行 > 环境变量 > dm_reg.txt > config.json。
    """
    return resolve_credentials(cli_value, None, cfg)[:2]


def build_parser(cfg):
    p = argparse.ArgumentParser(description="dm-mcp：大漠插件（DM）MCP 服务 v%s" % __version__)
    p.add_argument("--mode", choices=["stdio", "http"], default="stdio", help="前端模式，默认 stdio")
    p.add_argument("--host", default="127.0.0.1")
    p.add_argument("--port", type=int, default=int(cfg.get("http_port", DEFAULT_HTTP_PORT)))
    p.add_argument("--dm-path", default=cfg.get("dm_path"), help="dm.dll 绝对路径")
    p.add_argument("--reg-code", default=None, help="DM 注册码（优先级最高；建议改用 dm_reg.txt 或环境变量 DM_REG_CODE）")
    p.add_argument("--extra-code", default=cfg.get("extra_code"),
                   help="DM 附加码（Reg 的第 2 个参数，注册时填写的自定义字符串；"
                        "也可用 dm_reg.txt 的 extra_code / 环境变量 DM_EXTRA_CODE）")
    p.add_argument("--backend", choices=["auto", "dll", "com"], default=cfg.get("backend", "auto"))
    p.add_argument("--guard-modes", default=",".join(cfg.get("guard_modes", ["memory2", "b3"])),
                   help="盾模式，逗号分隔，默认 memory2,b3")
    p.add_argument("--asm-timeout", type=int, default=int(cfg.get("asm_timeout_ms", 10000)))
    p.add_argument("--no-guard", action="store_true",
                   help="启动加载时不加载盾（仅供诊断；内存接口将全部被拒绝）")
    p.add_argument("--token", default=cfg.get("token"), help="HTTP 模式访问令牌（可选，请求头 X-DM-Token）")
    p.add_argument("--check", action="store_true", help="运行自检后退出")
    p.add_argument("--allow-write", action="store_true", help="自检时允许对目标进程做写测试（默认只读）")
    p.add_argument("--window-class", default=cfg.get("window_class", "UnrealWindow"))
    p.add_argument("--window-title", default=cfg.get("window_title", "剑灵"))
    p.add_argument("--module", default=cfg.get("module", "bnsr.exe"))
    # ---- 32 位宿主自举 ----
    p.add_argument("--python32", default=cfg.get("python32_path"),
                   help="32 位 python.exe 绝对路径（宿主自举用；也可用 config.json 的 python32_path "
                        "或环境变量 DM_MCP_PYTHON32）")
    p.add_argument("--no-relaunch", action="store_true",
                   help="不自动“64 位重拉为 32 位”（仅在 64 位下查看引导信息时使用）")
    # ---- 启动默认绑定《剑灵》 ----
    p.add_argument("--auto-bind", dest="auto_bind", action="store_true",
                   default=bool(cfg.get("auto_bind", True)),
                   help="未传 --hwnd 时，启动自动查找并绑定《剑灵》窗口（默认开启；可用 config.json 的 auto_bind 配置）")
    p.add_argument("--no-autobind", dest="auto_bind", action="store_false",
                   help="关闭启动时的自动窗口查找（与 --hwnd 同用时无影响：有 --hwnd 就不查找）")
    p.add_argument("--hwnd", default=cfg.get("hwnd"),
                   help="**显式指定要绑定的窗口句柄**（如 0x1102B2 或 1114802）。"
                        "给了它就严格绑定该句柄、完全不做窗口查找与类名/标题复核；"
                        "这是最稳的用法（自动查找可能误绑到标题含“剑灵”的第三方窗口）")
    return p


def parse_hwnd(raw):
    """把 ``--hwnd`` / config.json 的 hwnd 解析成 int；解析不了返回 ``None``。

    兼容三种常见写法（都实测用过）：``"0x1102B2"``（十六进制）、``"1114802"``（十进制）、
    以及 JSON 里直接写数字。解析失败**不抛异常**，只记一条日志 ——
    启动流程不该因为一个可选参数写错就整个起不来。
    """
    if raw is None or raw == "":
        return None
    if isinstance(raw, bool):
        return None
    if isinstance(raw, int):
        return raw or None
    s = str(raw).strip()
    try:
        v = int(s, 0)          # 支持 0x 前缀与纯十进制
    except ValueError:
        SRV.log("--hwnd 解析失败：%r（既不是十进制也不是 0x 十六进制，已忽略）" % raw)
        return None
    if v == 0:
        SRV.log("--hwnd = 0 无意义（0 表示“未指定”），已忽略")
        return None
    return v


def print_host_check(stream=None):
    """宿主位数自检输出。stdio 模式下必须写 stderr：stdout 只能放 JSON-RPC 报文。"""
    stream = stream if stream is not None else sys.stdout
    h = HOST.current_host()
    ok = h["bits"] == 32
    stream.write("宿主位数检查：%s（%s）\n" % (
        "32 位 OK" if ok else "64 位 —— 不符合要求",
        "符合 dm.dll 要求" if ok else "dm.dll 为 x86 组件，必须 32 位宿主，入口会自动重拉"))
    stream.write("宿主解释器：%s（Python %s）\n" % (h["exe"], h["python"]))
    stream.flush()
    return ok


def _autobind_summary(info):
    """把 auto_bind 结果压成一行日志。"""
    if not info:
        return "未执行"
    if info.get("ok"):
        s = "绑定成功 %s（来源：%s）" % (info.get("bound_hwnd"), info.get("source"))
        if info.get("warning"):
            s += "；" + info["warning"]
        return s
    return "绑定未完成：%s（%s）" % (info.get("error"), info.get("hint"))


def main(argv=None):
    argv = list(sys.argv[1:] if argv is None else argv)
    cfg = load_config()
    args = build_parser(cfg).parse_args(argv)
    guard_modes = [m.strip() for m in str(args.guard_modes).split(",") if m.strip()]
    reg_code, extra_code, reg_src = resolve_credentials(args.reg_code, args.extra_code, cfg)

    # ---- 0) 宿主位数自举：64 位则自动用 32 位解释器重新拉起自身 ----
    probe_stream = sys.stderr if args.mode == "stdio" else sys.stdout
    HOST.ensure_32bit_host(ENTRY_SCRIPT, argv=argv, cfg=cfg, explicit_python32=args.python32,
                           auto_relaunch=not args.no_relaunch, stream=probe_stream, log=SRV.log)
    print_host_check(None if args.mode == "http" else sys.stderr)
    SRV.log(HOST.host_report_line())

    SRV.log("启动参数：mode=%s backend=%s dm_path=%s guard_modes=%s python32=%s auto_bind=%s "
            "reg_code=%s extra_code=%s" %
            (args.mode, args.backend, args.dm_path, guard_modes, args.python32, args.auto_bind,
             ("已提供（来源：%s）" % reg_src) if reg_code else "未提供",
             "已提供" if extra_code else "未提供"))

    core = DmCore(dm_path=args.dm_path, reg_code=reg_code, extra_code=extra_code,
                  backend=args.backend,
                  guard_modes=guard_modes, asm_timeout_ms=args.asm_timeout,
                  http_port=args.port, window_class=args.window_class)

    if args.check:
        import selftest
        return selftest.run(core, window_class=args.window_class, window_title=args.window_title,
                            module=args.module, allow_write=args.allow_write,
                            hwnd=parse_hwnd(args.hwnd))

    # ================= 启动流程：① 创建 DM 对象 -> ② Reg -> ③ 绑定 hwnd =================
    # 为什么把三步拆开写日志：
    #   以前这三件事揉在 core.load() + core.auto_bind() 里，失败时日志只有一句
    #   "启动默认绑定：绑定未完成"，看不出卡在哪一步、也看不出"是没找到窗口"还是
    #   "找到了但绑不上"。现在窗口可以由参数传入（--hwnd / config.json: hwnd），
    #   绑定不再需要查找，每一步都能给出确定结论。
    #
    # ① + ②：创建 DM 对象（加载 dm.dll / 创建 dm.dmsoft COM）并 Reg 注册。
    #         加载失败仍允许起服务（便于在线诊断 / 随后 dm_load 重试）。
    try:
        core.load(guard=not args.no_guard)
        st = core.status()
        SRV.log("① 创建 DM 对象：backend=%s version=%s；② Reg 注册：%s" % (
            (st.get("backend") or {}).get("kind") if isinstance(st.get("backend"), dict) else st.get("backend"),
            st.get("dm_version"),
            "成功" if st.get("registered") else ("未提供注册码" if st.get("registered") is None else "失败")))
    except E.DmMcpError as exc:
        SRV.log("①/② 创建 DM 对象或 Reg 注册失败：%s（服务仍会启动，可随后在线调用 dm_load 重试）"
                % exc.to_dict())

    # ③ 绑定窗口：**有 hwnd 参数就严格绑定它**，没有才退回"自动查找"
    hwnd_explicit = parse_hwnd(args.hwnd)
    if hwnd_explicit is not None:
        # 严格路径：不查找、不复核。这是参数化后的推荐用法。
        try:
            out = core.bind_by_hwnd(hwnd_explicit)
            core._auto_bind = {
                "attempted": True, "time": time.strftime("%Y-%m-%d %H:%M:%S"),
                "ok": True, "source": "explicit-hwnd(--hwnd / config.json: hwnd)",
                "hwnd": hwnd_explicit, "bound_hwnd": out.get("bound_hwnd"),
                "guard_loaded": core._guard_loaded, "steps": [],
                "window_class": args.window_class, "window_title": args.window_title,
                "module": args.module, "error": None, "hint": None,
            }
            SRV.log("③ 绑定 hwnd %s：成功（hwnd 由参数传入，未做窗口查找）"
                    % out.get("bound_hwnd"))
            if not core._guard_loaded:
                SRV.log("⚠ 窗口已绑定，但 dm 盾未加载：内存读写/搜索接口仍会被拒绝")
        except E.DmMcpError as exc:
            core._auto_bind = {
                "attempted": True, "time": time.strftime("%Y-%m-%d %H:%M:%S"),
                "ok": False, "source": "explicit-hwnd(--hwnd / config.json: hwnd)",
                "hwnd": hwnd_explicit, "bound_hwnd": None,
                "guard_loaded": core._guard_loaded, "steps": [],
                "window_class": args.window_class, "window_title": args.window_title,
                "module": args.module, "error": exc.code, "bind_error": exc.to_dict(),
                "hint": ("传入的 hwnd %s 绑定失败。请确认：① 该句柄当前仍有效"
                         "（窗口重开会换 hwnd）；② 目标进程未退出；③ 服务以管理员身份运行。"
                         "也可调用 dm_find_window 重新取 hwnd 后用 dm_bind_window 绑定。"
                         % hex(hwnd_explicit)),
            }
            SRV.log("③ 绑定 hwnd %s：失败 -> %s（%s）"
                    % (hex(hwnd_explicit), exc.code, exc.message))
    elif not args.auto_bind:
        core._auto_bind = {"attempted": False, "skipped": True,
                           "reason": "未传 --hwnd 且自动查找已关闭"
                                     "（--no-autobind / config.json: auto_bind=false）"}
        SRV.log("③ 未绑定窗口：既没有 --hwnd，也关闭了自动查找")
    else:
        info = core.auto_bind(window_class=args.window_class, window_title=args.window_title,
                              module=args.module, hwnd=None)
        SRV.log("③ 未传 --hwnd，退回自动查找：%s" % _autobind_summary(info))

    if args.mode == "http":
        if SRV.port_in_use(args.host, args.port):
            print("端口 %d 已被占用（可能已有 dm-mcp 在运行）" % args.port)
            return 2
        SRV.serve_http(core, args.host, args.port, args.token)
        return 0

    SRV.serve_stdio(core)
    return 0


if __name__ == "__main__":
    sys.exit(main())
