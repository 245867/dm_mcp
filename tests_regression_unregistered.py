# -*- coding: utf-8 -*-
"""回归：未注册 DM 时，三个"原生接口"必须返回结构化错误，而不是让进程崩溃。

背景（2026-09-20 实测发现）：
    未注册状态下，以下 DM 接口会在内部解引用空指针并触发
    ``access violation reading 0x0`` —— 这是**进程级崩溃**，
    Python 的 try/except 兜不住，会直接把 MCP 服务打死：
        1) ``DmGuard``              （加载盾）
        2) ``BindWindow`` / ``BindWindowEx``（绑定窗口）
    触发点分别为 ``DmCore.load(guard=True)``、``DmCore.guard()``、``DmCore.bind_window()``。

期望（修复后）：
    - ``load()`` 在未注册时**跳过** DmGuard 与绑定尝试，正常返回 status；
    - 直接调用 ``guard()`` / ``bind_window()`` 抛出 ``DmMcpError``，进程存活。

本脚本不需要注册码、不需要游戏运行，是**离线可跑**的回归。
用法（必须 32 位 Python，dm.dll 为 x86 COM 组件）：
    <python32> tests_regression_unregistered.py
退出码：0=全部符合预期，1=仍有崩溃/行为不符，2=环境不符（非 32 位或缺 dm.dll）
"""
import ctypes
import os
import sys

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, HERE)

# dm.dll 候选位置：**只认通用位置与环境变量**，不写任何开发机绝对路径
# （开发机路径会泄露本机目录结构，且对别人无用）。找不到时用 DM_DLL 指定。
DM_DLL_CANDIDATES = [
    os.environ.get("DM_DLL", ""),
    os.path.join(HERE, "dm.dll"),
]


def find_dll():
    for p in DM_DLL_CANDIDATES:
        if os.path.isfile(p):
            return p
    return None


def main():
    if ctypes.sizeof(ctypes.c_void_p) != 4:
        print("[跳过] 需要 32 位 Python（dm.dll 是 x86 COM 组件）")
        return 2

    dll = find_dll()
    if not dll:
        print("[跳过] 未找到 dm.dll，检查过:", DM_DLL_CANDIDATES)
        return 2

    from dm_mcp.core import DmCore
    import dm_mcp.errors as E

    failures = []
    print("dm.dll =", dll)
    print()

    # ---- 用例 1：load() 未注册不应崩溃，且跳过盾 ----
    c = DmCore(dm_path=dll, reg_code="")
    try:
        st = c.load()
        print("[PASS] 1. load() 未崩溃；guard_loaded =", st["guard_loaded"])
        if st["guard_loaded"]:
            failures.append("1. 未注册时 guard_loaded 不应为 True")
        if not any(d.get("action") == "skipped-unregistered"
                   for d in st.get("guard_detail", [])):
            failures.append("1. guard_detail 缺少 skipped-unregistered 标记")
    except OSError as exc:
        failures.append("1. load() 触发访问违例（进程差点死掉）: %s" % exc)
    except E.DmMcpError as exc:
        print("[PASS] 1. load() 返回结构化错误:", exc.code)

    # ---- 用例 2：guard() 未注册应抛结构化错误 ----
    try:
        c.guard(True, ["memory2", "b3"])
        failures.append("2. 未注册时 guard() 竟然成功返回")
    except E.DmMcpError as exc:
        print("[PASS] 2. guard() 抛结构化错误:", exc.code)
    except OSError as exc:
        failures.append("2. guard() 触发访问违例（进程差点死掉）: %s" % exc)

    # ---- 用例 3：bind_window() 未注册应抛结构化错误 ----
    fake_hwnd = 0x1  # 未注册时应在触达 DM 之前就被拦住，句柄是否真实无关
    try:
        c.bind_window(fake_hwnd)
        failures.append("3. 未注册时 bind_window() 竟然成功返回")
    except E.DmMcpError as exc:
        print("[PASS] 3. bind_window() 抛结构化错误:", exc.code)
    except OSError as exc:
        failures.append("3. bind_window() 触发访问违例（进程差点死掉）: %s" % exc)

    # ---- 用例 4：auto_bind() 不抛异常，且给出可读 error ----
    try:
        info = c.auto_bind(window_class="UnrealWindow", window_title="剑灵", module="bnsr.exe")
        ok = info.get("ok")
        print("[PASS] 4. auto_bind() 未崩溃；ok =", ok, "| error =", info.get("error"))
        if ok:
            print("        （注：本机已注册且游戏在跑，此用例不做强断言）")
    except OSError as exc:
        failures.append("4. auto_bind() 触发访问违例（进程差点死掉）: %s" % exc)

    print()
    if failures:
        for f in failures:
            print("[FAIL]", f)
        return 1
    print("[OK] 全部符合预期：未注册时三个原生接口均安全失败，无进程崩溃")
    return 0


if __name__ == "__main__":
    sys.exit(main())
