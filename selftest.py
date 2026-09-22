# -*- coding: utf-8 -*-
"""自检脚本：验证“服务能启动 -> 盾能加载 -> 能对目标进程完成一次真实内存读写”。

安全默认：
    - 默认 **只读**（读目标进程模块基址前 4 字节，校验 MZ 头 0x905A4D）；
    - 写测试必须显式 --allow-write，且只写 **自己通过 VirtualAllocEx 申请的临时内存**
      （不触碰游戏自身数据结构），写入后立即读回校验，最后尝试 VirtualFreeEx 释放。
"""
import json
import sys
import time

from dm_mcp import errors as E
from dm_mcp.core import num

MZ = 0x905A4D


def _step(no, title, fn):
    print("\n[%s] %s" % (no, title))
    t0 = time.time()
    try:
        out = fn()
        dt = (time.time() - t0) * 1000
        print("    OK  (%d ms)  %s" % (dt, json.dumps(out, ensure_ascii=False, default=str)[:600]))
        return True, out
    except Exception as exc:
        dt = (time.time() - t0) * 1000
        if isinstance(exc, E.DmMcpError):
            print("    FAIL(%d ms) %s" % (dt, json.dumps(exc.to_dict(), ensure_ascii=False)))
        else:
            print("    FAIL(%d ms) %s: %s" % (dt, type(exc).__name__, exc))
        return False, None


def run(core, window_class="UnrealWindow", window_title="剑灵", module="bnsr.exe", allow_write=False,
        hwnd=None):
    """自检：① 创建 DM 对象 -> ② Reg -> ③ 加载盾 -> ④ 绑定窗口 -> ⑤ 真实内存读写。

    Args:
        hwnd: **显式指定的窗口句柄**（十进制 int 或 ``"0x1102B2"``）。
              给了它就跳过第 3 步的"查找窗口"与第 3.5 步的"类名校验"，直接绑这个句柄 ——
              这正是"窗口 hwnd 由参数传入"的用法：调用方已经知道要绑哪个窗口时，
              再去找一遍既多余，也可能因为类名/标题复核把用户自己选的窗口误判掉。
    """
    print("=" * 78)
    print("dm-mcp 自检：加载 -> 注册 -> 加载盾 -> 绑定目标 -> 真实内存读写")
    print("=" * 78)
    results = {}

    ok, out = _step(1, "加载 dm.dll / 创建 dm.dmsoft 并加载盾", lambda: core.load(guard=True))
    results["load_and_guard"] = ok
    if not ok:
        print("\n自检中止：DM 未就绪（请检查 32 位宿主 / dm.dll 路径 / 注册码 / 管理员权限）")
        return 1

    ok, out = _step(2, "读取状态（盾状态必须为 true）", lambda: core.status())
    results["status"] = ok
    if ok and not out.get("guard_loaded"):
        print("\n自检中止：dm 盾未加载，内存接口不可用")
        print("提示：若 notes 里出现 '未提供注册码' / 'Reg 失败'，说明凭据未配置或与本机机器码不匹配；")
        print("      未注册时 DmGuard / BindWindow 会硬崩，服务已主动阻止这两类调用（这是保护，不是故障）。")
        return 1

    explicit = None
    if hwnd not in (None, "", 0):
        explicit = num(hwnd) if not isinstance(hwnd, int) else hwnd
        if not explicit:
            print("\n--hwnd 解析失败：%r" % (hwnd,))
            return 2
        print("[跳过] 未做窗口查找：hwnd 由参数传入 -> %s" % hex(explicit))
        results["find_window"] = True
        # 汇总表只认 True/False/None（见文件末尾的映射），所以要给 None 而不是字符串，
        # 否则会被当成未知键 KeyError 打崩整个自检 —— "跳过"的语义本来就是 None。
        results["class_name"] = None

    if explicit is None:
        ok, out = _step(3, "查找目标窗口（class=%s, 标题含 %s）" % (window_class, window_title),
                        lambda: core.find_window(window_class, window_title))
        results["find_window"] = ok and bool(out and out.get("hwnd"))
        hwnd = (out or {}).get("hwnd") or 0
        if not hwnd:
            print("\n未找到目标窗口：游戏/目标程序可能未运行。"
                  "\n服务与盾均已就绪，可稍后在目标运行后调用 dm_find_window / dm_bind_window。")
            return 3

        # 新增：类名可读性 + 严格校验（防止误绑同名标题的第三方工具窗口）
        def _class_probe():
            cn = core._window_class(hwnd)
            if cn != window_class:
                raise RuntimeError("类名实测为 %r，期望 %r（可能绑到了同名标题的其他窗口）"
                                   % (cn, window_class))
            return {"class_name": cn}

        ok, out = _step(3.5, "窗口类名校验（应为 %s）" % window_class, _class_probe)
        results["class_name"] = ok
    else:
        hwnd = explicit

    ok, out = _step(4, "绑定窗口 + SetAsmHwndAsProcessId", lambda: core.bind_window(hwnd))
    results["bind"] = ok

    ok, out = _step(5, "取模块基址（GetModuleBaseAddr %s）" % module,
                    lambda: core.get_module_base_addr(module))
    results["module_base"] = ok
    base = (out or {}).get("base") or 0

    if base:
        ok, out = _step(6, "真实读内存：读模块基址首 4 字节（应为 0x905A4D，即 MZ 头）",
                        lambda: core.read_int("0x%X" % base, 0))
        good = ok and (int(out.get("value", 0)) & 0xFFFFFF) == MZ
        results["read_mz"] = good
        print("    -> MZ 校验：%s" % ("通过" if good else "未通过（读出值 0x%X）" % int((out or {}).get("value", 0))))
    else:
        results["read_mz"] = False
        print("\n跳过读测试：未取到模块基址（模块名可能不对，如 bnsr.exe / BNSR.exe）")

    if allow_write:
        def _write_test():
            # DM 的真实签名：VirtualAllocEx(hwnd,addr,size,type) —— 4 参、无 protect；
            # type=1 表示 64 位模式（剑灵是 64 位目标，必须用 1）。
            alloc = core.virtual_alloc_ex(size=0x100, type=1)
            addr = alloc["address"]
            marker = 0x1122334455667788
            core.write_int(addr, marker, type=3)          # 仅写自己申请的临时内存
            back = core.read_int(addr, type=3)["value"]
            # VirtualFreeEx(hwnd,addr) —— 只有 2 参，无 size/type
            free = core.virtual_free_ex(addr)
            return {"alloc": hex(addr), "written": hex(marker), "readback": hex(back),
                    "match": back == marker, "free_ret": free.get("ret")}
        ok, out = _step(7, "真实写内存：在目标进程申请 0x100 临时内存 -> 写 8 字节 -> 读回校验 -> 释放",
                        _write_test)
        results["write_roundtrip"] = ok and bool(out and out.get("match"))
    else:
        print("\n[7] 真实写内存：已跳过（默认只读）。需要时加 --allow-write，"
              "写测试仅作用于本服务申请的临时内存。")
        results["write_roundtrip"] = None

    print("\n" + "=" * 78)
    print("自检结论：")
    for k, v in results.items():
        # 用 .get 兜底：万一某个新增步骤写进了第三种取值，也不该把汇总表打崩
        # （踩过一次：class_name 曾写成 "skipped(...)" 字符串 -> KeyError 直接中断自检）。
        print("    %-16s %s" % (k, {True: "通过", False: "失败", None: "跳过"}.get(v, str(v))))
    all_read = all(results.get(k) for k in ("load_and_guard", "status", "bind", "module_base", "read_mz"))
    print("只读链路：%s" % ("全部通过" if all_read else "存在失败项"))
    if results.get("write_roundtrip") is True:
        print("读写链路：全部通过（读写能力已实测）")
    print("=" * 78)
    return 0 if all_read else 1


if __name__ == "__main__":
    import os
    sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
    from run_server import main

    # ⚠ 必须**强制补上 --check**（实测踩坑）：
    #   旧实现是直接 `sys.exit(main())`，没传 --check，于是 `python selftest.py`
    #   并不会自检 —— 它会退化成"启动 stdio 服务"，然后因为 stdin 立即结束而
    #   打印几行启动日志就退出。看日志像是"跑完了"，实际一个检查项都没执行，
    #   是个很难被发现的假绿。
    #
    #   委托给 run_server.main() 而不是在这里自己拼 DmCore，是为了复用它的：
    #   32 位宿主自动自举、config.json 读取、注册码解析（--reg-code / dm_reg.txt）、
    #   hwnd 解析（"0x1102B2" / 十进制）。重复实现一份必然和主入口漂移。
    argv = [a for a in sys.argv[1:] if a != "--check"] + ["--check"]
    sys.exit(main(argv))
