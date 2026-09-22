# -*- coding: utf-8 -*-
"""HTTP 端到端回归：验证关键路径既不崩、语义也正确。

前置：先启动 HTTP 服务（32 位宿主）
    <python32> run_server.py --mode http --port 27043 --hwnd 0x1102B2

用法：
    python tests_http_regression.py [port] [hwnd]

为什么本脚本要**区分"已注册 / 未注册"两种模式**：
    这两种模式下同一接口的正确行为是**相反的**，写死任何一种期望都会在另一种模式下误报。
      * 未注册：DmGuard / BindWindow 在 DM 内部会解引用空指针**硬崩整个进程**，
                所以服务的正确行为是**主动拒绝**并返回 DM_NOT_REGISTERED；
      * 已注册：这两个接口就该正常返回 200，此时若还断言 DM_NOT_REGISTERED，
                等于把"服务工作正常"判成失败（早期版本就踩过这个坑）。
    脚本先读一次 dm_status 判断当前模式，再按对应期望校验。
"""
import json
import sys
import urllib.error
import urllib.request

PORT = int(sys.argv[1]) if len(sys.argv) > 1 else 27043
# 目标窗口句柄：不同机器的《剑灵》窗口 hwnd 不同，且窗口重开就会变，故做成参数。
# 默认值只是"本机曾经用过的一个句柄"，取不到目标时相关用例会自动降级为跳过。
HWND = sys.argv[2] if len(sys.argv) > 2 else "0x1102B2"

BASE = "http://127.0.0.1:%d" % PORT

# 绕过系统代理，确保直连本地
opener = urllib.request.build_opener(urllib.request.ProxyHandler({}))


def call(method, path, body=None):
    data = json.dumps(body).encode() if body is not None else None
    req = urllib.request.Request(BASE + path, data=data, method=method)
    if data:
        req.add_header("Content-Type", "application/json")
    try:
        with opener.open(req, timeout=20) as r:
            return r.status, r.read().decode("utf-8", "replace")
    except urllib.error.HTTPError as e:
        return e.code, e.read().decode("utf-8", "replace")
    except Exception as e:
        return None, "CONN-FAIL: %s" % e


def main():
    failures = []
    print("=" * 74)
    print("HTTP 端到端回归 @ %s" % BASE)
    print("=" * 74)

    # 0. 先判定当前实例处于哪种模式（已注册 / 未注册）—— 后续用例的期望值依赖它
    s, t = call("GET", "/api/dm_status")
    if s != 200:
        print("\n无法连接服务（HTTP %s）：%s" % (s, t[:200]))
        print("请先启动： <python32> run_server.py --mode http --port %d --hwnd %s" % (PORT, HWND))
        return 2
    st = json.loads(t)
    registered = st.get("registered")
    guard_loaded = st.get("guard_loaded")
    bound_hwnd = st.get("bound_hwnd")
    target_class = st.get("window_class")
    print("\n[0] 模式判定：registered=%s guard_loaded=%s dm_version=%s bound_hwnd=%s"
          % (registered, guard_loaded, st.get("dm_version"), bound_hwnd))
    print("    期望基准：%s" % ("已注册 -> 盾/绑定类接口应正常放行"
                              if registered else
                              "未注册 -> 盾/绑定类接口应被主动拒绝（DM_NOT_REGISTERED）"))
    if bound_hwnd:
        # 顺带校验服务报告的句柄确实是我们要的那个（防止 --hwnd 被忽略而悄悄自动绑定）
        if str(bound_hwnd).lower() != str(HWND).lower():
            failures.append("0. 服务绑定的是 %s，与期望 %s 不一致（--hwnd 可能没生效）"
                            % (bound_hwnd, HWND))

    # 1. tools/list 数量
    #    46 -> 47：新增 dm_bind_hwnd（严格绑定指定 hwnd，参数传入、不做窗口查找）。
    #    这个数字就是"工具清单是否被意外增删"的哨兵，改动工具时同步更新它。
    s, t = call("GET", "/tools")
    n = 0
    try:
        d = json.loads(t)
        n = len(d.get("tools", d if isinstance(d, list) else []))
    except Exception:
        pass
    print("\n[1] GET /tools -> HTTP %s, tools=%d" % (s, n))
    if s != 200 or n != 47:
        failures.append("1. tools 列表异常（期望 200/47）")
    else:
        # 注意：/tools 返回的是**字符串数组**（["dm_load", "dm_status", ...]），
        # 不是 [{"name": ...}] 形式的 dict 列表。这里两种形状都兼容，
        # 免得以后换了序列化格式又把回归测试自己搞崩。
        names = {x if isinstance(x, str) else x.get("name")
                 for x in json.loads(t).get("tools", [])}
        for must in ("dm_bind_hwnd", "dm_bind_window", "dm_status", "dm_read_int"):
            if must not in names:
                failures.append("1b. 工具清单缺少 %s" % must)

    # 2. dm_status 不阻塞、不死
    print("\n[2] GET /api/dm_status -> HTTP %s（见 [0]）" % s)

    # 3. dm_guard：未注册 -> 结构化拒绝；已注册 -> 正常放行
    s, t = call("POST", "/api/dm_guard", {})
    print("\n[3] POST /api/dm_guard -> HTTP %s" % s)
    print("    ", t[:260])
    if registered:
        if s != 200:
            failures.append("3. 已注册模式下 dm_guard 未返回 200")
    elif "DM_NOT_REGISTERED" not in t:
        failures.append("3. 未注册模式下 dm_guard 未返回 DM_NOT_REGISTERED")

    # 4. 绑定类接口（同上，两种模式期望相反）
    s, t = call("POST", "/api/dm_bind_window", {"hwnd": HWND})
    print("\n[4] POST /api/dm_bind_window {hwnd:%s} -> HTTP %s" % (HWND, s))
    print("    ", t[:260])
    if registered:
        if s != 200:
            failures.append("4. 已注册模式下 dm_bind_window 未返回 200")
    elif "DM_NOT_REGISTERED" not in t:
        failures.append("4. 未注册模式下 dm_bind_window 未返回 DM_NOT_REGISTERED")

    # 4b. dm_bind_hwnd：**本次新增的严格绑定路径**
    s, t = call("POST", "/api/dm_bind_hwnd", {"hwnd": HWND})
    print("\n[4b] POST /api/dm_bind_hwnd {hwnd:%s} -> HTTP %s" % (HWND, s))
    print("    ", t[:260])
    if registered:
        if s != 200:
            failures.append("4b. 已注册模式下 dm_bind_hwnd 未返回 200")
        else:
            d = json.loads(t)
            payload = d.get("result", d)
            if payload.get("source") != "explicit-hwnd":
                failures.append("4b. dm_bind_hwnd 未回显 source=explicit-hwnd（走错了路径）")
            if str(payload.get("bound_hwnd", "")).lower() != str(HWND).lower():
                failures.append("4b. dm_bind_hwnd 绑定结果与传入 hwnd 不一致")
    else:
        if "DM_NOT_REGISTERED" not in t:
            failures.append("4b. 未注册模式下 dm_bind_hwnd 未返回 DM_NOT_REGISTERED")

    # 4c. hwnd 传 0 -> 必须是 NO_TARGET 且**不能崩服务**（严格路径的入参校验）
    s, t = call("POST", "/api/dm_bind_hwnd", {"hwnd": 0})
    print("\n[4c] POST /api/dm_bind_hwnd {hwnd:0} -> HTTP %s (期望 DM_NO_TARGET)" % s)
    print("    ", t[:200])
    if "DM_NO_TARGET" not in t:
        failures.append("4c. hwnd=0 未返回 DM_NO_TARGET")

    # 5. dm_get_class_name（兼容层）应可用：GetWindowClass / GetClassName 二选一
    #
    #    这一条曾经真的挂过，所以现在必须断言、不能只打印：
    #    dispatch 里 dm_get_class_name 走的是 a.get("hwnd") 原样透传，
    #    不像 dm_bind_window 那样套了 _u64()；而 core._target() 当时用的是裸
    #    int()，于是传 "0x1102B2" 会抛 ValueError 并被兜成 DM_INTERNAL
    #    （消息里还带 Python 内部异常文案，看着像框架崩了）。
    #    已在 core 侧统一改为 num()；这里留断言防止再退化。
    s, t = call("POST", "/api/dm_get_class_name", {"hwnd": HWND})
    print("\n[5] POST /api/dm_get_class_name {hwnd:%s} -> HTTP %s" % (HWND, s))
    print("    ", t[:200])
    if s != 200:
        failures.append("5. dm_get_class_name 未返回 200")
    elif "DM_INTERNAL" in t:
        failures.append("5. dm_get_class_name 抛内部异常（十六进制 hwnd 未被解析）")
    elif registered and bound_hwnd:
        # 已绑定成功时，类名必须真的读得出来且与目标窗口一致
        try:
            payload = json.loads(t)
            payload = payload.get("result", payload)
            got = str(payload.get("class_name") or "")
        except Exception:
            got = ""
        if not got:
            failures.append("5. dm_get_class_name 返回空类名（期望非空）")
        elif target_class and got != target_class:
            failures.append("5. 类名与 dm_status 报告的不一致：%r != %r" % (got, target_class))

    # 6. 服务仍然存活（关键：前面调了会崩的接口）
    s, t = call("GET", "/api/dm_status")
    print("\n[6] 存活复查 GET /api/dm_status -> HTTP %s" % s)
    if s != 200:
        failures.append("6. 服务已死（之前的调用把它打崩了）")

    # 7. 未知工具 -> 400
    s, t = call("POST", "/api/dm_no_such_tool", {})
    print("\n[7] POST /api/dm_no_such_tool -> HTTP %s (期望 400)" % s)
    if s != 400:
        failures.append("7. 未知工具未返回 400")

    # 8. 真读一枪：模块基址首 4 字节 = MZ 头（只有已注册 + 盾已加载才可能通过）
    if registered and guard_loaded:
        s, t = call("POST", "/api/dm_read_int", {"addr": "0x140000000", "type": 0})
        print("\n[8] POST /api/dm_read_int {addr:0x140000000} -> HTTP %s" % s)
        print("    ", t[:200])
        try:
            v = json.loads(t).get("value")
        except Exception:
            v = None
        if v != 0x905A4D:
            failures.append("8. 模块基址首 4 字节不是 MZ 头（得到 %r，期望 9460301）" % v)
    else:
        print("\n[8] 真读校验：跳过（需要 registered=True 且 guard_loaded=True）")

    print("\n" + "=" * 74)
    if failures:
        for f in failures:
            print("[FAIL]", f)
        return 1
    print("[OK] HTTP 端到端回归全部通过（且服务未崩溃）")
    return 0


if __name__ == "__main__":
    sys.exit(main())
