# -*- coding: utf-8 -*-
"""DM 能力核心：生命周期（Reg/盾）、窗口绑定、内存读写、内存搜索、内存操作。

本层是唯一持有 DM 状态的地方（常驻进程语义就体现在这里：屏蔽/绑定/超时等状态跨调用保持）。
"""
import base64
import binascii
import ctypes
import os
import threading
import time

from . import DEFAULT_HTTP_PORT
from . import backend as BK
from . import errors as E
from . import hostenv as HOST

# ReadInt/WriteInt 的 type 语义（本机实测，DM 官方一致）
WIDTH_BY_TYPE = {3: 8, 0: 4, 1: 2, 2: 1, 4: 4, 5: 2, 6: 1}
TYPE_BY_WIDTH = {8: 3, 4: 0, 2: 1, 1: 2}
SIGNED_TYPES = {0, 1, 2, 3}
DEFAULT_GUARD_MODES = ["memory2", "b3"]


def addr_str(addr):
    """把地址转成 DM 能正确解析的**十六进制字符串**（``"0x140000000"``）。

    为什么必须这样（实测教训，2026-09-20，DM 7.2607 + COM 后端）：
        所有接受地址的 DM 接口（``ReadInt`` / ``WriteInt`` / ``ReadString`` /
        ``WriteString`` / ``ReadDataAddr`` / ``FindInt`` 等）在**传十进制字符串时
        不报错、也不置 GetLastError，而是静默返回 0**：

            ReadInt(hwnd, "0x140000000", 3) -> 12894362189   # 低 32 位 = 0x905A4D = 'MZ' ✅
            ReadInt(hwnd, "5368709120", 3)  -> 0             # 静默返回 0 ❌

        这属于**最危险的一类 bug**：调用方看到的是"读写成功但值全是 0"，
        而不是任何一个可追踪的错误码。因此全项目统一走本函数，
        绝不要在各处手写 ``str(addr)``。

    Args:
        addr: int / 十六进制字符串（``"0x140000000"``）/ 十进制数字字符串。

    Returns:
        ``"0x..."`` 形式的十六进制字符串；无法解析时返回 ``"0x0"``。
    """
    return hex(num(addr))


def addr_str_range(addr_range):
    """规范化内存搜索的地址范围串，统一成 ``"0x起始-0x结束"``。

    与 :func:`addr_str` 同源问题：DM 的 FindInt/FindFloat/... 只认十六进制地址。
    调用方可能传 ``"0x140000000-0x150000000"``（已正确）、``"5368709120-5637144576"``
    （十进制，会搜不到任何结果）或 ``"0x140000000:0x150000000"``（分隔符写法差异）。

    本函数把两端都归一为 hex，并按 DM 要求的 ``-`` 连接；
    若传入的本来就不是范围（无法切分），原样返回交给 DM 报错，不掩盖真实问题。

    Args:
        addr_range: 范围串/单个地址，如 ``"0x140000000-0x150000000"``。

    Returns:
        归一后的 ``"0x...-0x..."``；输入为空或不可解析时原样返回。
    """
    if addr_range is None:
        return addr_range
    s = str(addr_range).strip()
    if not s:
        return s
    # 分隔符兼容：DM 用 '-'，也允许调用方写 ':' 或 '~'
    for sep in ("-", "~", ":"):
        if sep in s:
            left, _, right = s.partition(sep)
            left, right = left.strip(), right.strip()
            if left and right:
                return "%s-%s" % (addr_str(left), addr_str(right))
            return s
    # 单地址（无范围）：DM 的 Find* 要求范围，这里也补成 [addr, addr]
    return "%s-%s" % (addr_str(s), addr_str(s))


def num(value):
    """把 DM 返回值统一成 int：兼容 int / float / '0x140000000' / '404102' / BSTR / None。

    DM 的不同后端与不同版本对同一接口可能返回整数或字符串（尤其地址类），
    统一在此归一，避免把字符串当 0 或被 int('0x..') 抛异常打断。
    """
    if value is None:
        return 0
    if isinstance(value, bool):
        return int(value)
    if isinstance(value, int):
        return value
    if isinstance(value, float):
        return int(value)
    s = str(value).strip()
    if not s:
        return 0
    try:
        return int(s, 0)
    except ValueError:
        pass
    try:
        return int(s)
    except ValueError:
        return 0


class DmCore(object):
    """DM 能力核心。

    本类是所有 DM 状态的唯一持有者（盾标记、绑定 hwnd、超时、加载备注等），
    设计为“加载一次、长期服务”的常驻对象；实例方法对 DM 的调用通过 ``self._lock``
    串行化，以适配 DM 的 STA（单线程公寓）模型。

    Args:
        dm_path: dm.dll 绝对路径；``None`` 表示由 backend 自动探测。
        reg_code: 注册码；``None`` 表示不调用 Reg（盾通常将加载失败）。
        extra_code: DM 附加码（``Reg`` 的第 2 个参数），注册时填写的自定义字符串。
        backend: ``auto`` | ``dll`` | ``com``。
        guard_modes: 盾模式列表，默认 ``["memory2", "b3"]``。
        asm_timeout_ms: ``AsmSetTimeout`` 的超时毫秒数。
        target_hwnd: 预设目标窗口句柄（可选）。
        http_port: HTTP 模式实际监听端口，仅用于 ``status()`` 如实回显。
        window_class: 目标窗口类名，仅用于 ``status()`` 回显与诊断。
    """

    def __init__(self, dm_path=None, reg_code=None, extra_code=None, backend="auto", guard_modes=None,
                 asm_timeout_ms=10000, target_hwnd=None, http_port=None, window_class=None):
        self.dm_path = dm_path
        self.reg_code = reg_code
        self.extra_code = "" if extra_code is None else str(extra_code)
        self.backend_kind = backend
        self.guard_modes = list(guard_modes or DEFAULT_GUARD_MODES)
        self.asm_timeout_ms = asm_timeout_ms
        # 仅供 status() 如实回显（不影响 DM 行为）：HTTP 端口与目标窗口类名
        self.http_port = int(http_port) if http_port else DEFAULT_HTTP_PORT
        self.window_class = window_class

        self._be = None
        self._lock = threading.RLock()
        self._guard_loaded = False
        self._guard_detail = []
        self._reg_ok = None
        self._hwnd = None
        self._notes = []
        self._version = None
        self._auto_bind = None      # 最近一次“启动默认绑定”的结果（随 dm_status 返回）
        if target_hwnd:
            self._hwnd = int(target_hwnd)

    # ------------------------------------------------------------ 生命周期
    def load(self, dm_path=None, reg_code=None, backend=None, guard=True, extra_code=None):
        """加载 dm.dll（或 COM），Reg 注册；guard=True 时立即加载 dm 盾。"""
        with self._lock:
            if dm_path:
                self.dm_path = dm_path
            if reg_code:
                self.reg_code = reg_code
            if extra_code is not None:
                self.extra_code = str(extra_code)
            if backend:
                self.backend_kind = backend
            be, notes = BK.create_backend(self.dm_path, self.backend_kind)
            self._be = be
            self._notes = notes
            self._guard_loaded = False
            self._guard_detail = []
            self._reg_ok = None
            self._version = None
            # dm 需要 SetPath 指向资源目录（dm.dll 所在目录，而非 dll 文件本身）
            dll_file = BK.locate_dm_dll(self.dm_path)[0]
            if dll_file:
                dll_dir = os.path.dirname(os.path.abspath(dll_file))
                try:
                    self._be.call("SetPath", dll_dir)
                    self._notes.append("SetPath -> %s（dm.dll 所在目录）" % dll_dir)
                except E.DmMcpError as exc:
                    self._notes.append("SetPath 失败（不影响内存接口）：%s" % exc.message)
            if self.reg_code:
                self._reg_ok = self.reg(self.reg_code, self.extra_code)
            else:
                self._reg_ok = None
                self._notes.append("未提供注册码（Reg 未调用）；如需完整能力请在 config.json / --reg-code 中配置")
            try:
                self._version = self._be.call("Ver")
            except E.DmMcpError:
                self._version = None
            if guard:
                if self._reg_ok is None:
                    # 未提供注册码：**绝不可**调用 DmGuard。
                    # 实测在未注册状态下 DmGuard 会解引用空内部指针 ->
                    # "access violation reading 0x0"，直接崩掉整个宿主进程
                    # （不是可捕获的 DM 错误码）。因此这里主动拒绝，并给出可操作的提示。
                    self._guard_loaded = False
                    self._guard_detail = [
                        {"mode": m, "ret": None, "action": "skipped-unregistered",
                         "note": "未注册，已跳过 DmGuard（调用会触发访问违例）"}
                        for m in self.guard_modes]
                    self._notes.append(
                        "未提供注册码：已跳过盾加载。内存接口将全部返回 DM_GUARD_NOT_LOADED。"
                        "请设置环境变量 DM_REG_CODE / DM_MCP_REG_CODE，或放置 dm_reg.txt。")
                elif not self._reg_ok:
                    # 提供了注册码但 Reg 失败（如机器码不匹配）：同样不能碰 DmGuard。
                    self._guard_loaded = False
                    self._guard_detail = [
                        {"mode": m, "ret": None, "action": "skipped-reg-failed",
                         "note": "Reg 失败，已跳过 DmGuard"}
                        for m in self.guard_modes]
                    self._notes.append(
                        "Reg 失败：已跳过盾加载。请确认注册码与本机机器码匹配，并以管理员身份运行。")
                else:
                    self.guard(True, self.guard_modes)
            return self.status()

    def reg(self, code, extra_code=None):
        """``Reg(code, second)`` -> 1 成功 / 0 失败。

        DM 的 Reg 是**双参数**接口：``Reg(注册码, 附加码)``。
        实测（2026-09-20，DM 7.2607 + COM）：
            * 只传 1 个参数 -> ``DM_CALL_FAILED``（COM 层参数个数不匹配）；
            * 第 2 参传 ``附加码`` / ``"7.2301"`` / ``""`` 时返回值均为 1 ——
              即 DM **不校验**第 2 参内容。但按官方约定应传"附加码"
              （注册时填写的自定义字符串，属个人凭据，不写入代码），
              填错虽不报错，但属配置不实，日后换版本/换机器容易踩坑。

        Args:
            code: 注册码。
            extra_code: 附加码；``None`` 时取实例配置（默认 ``""``）。
        """
        with self._lock:
            self._ensure_loaded()
            second = self.extra_code if extra_code is None else extra_code
            second = "" if second is None else str(second)
            ret = self._be.call("Reg", code, second)
            if int(ret) != 1:
                self._notes.append("Reg 返回 %s（失败）：部分高级接口与盾模式可能不可用" % ret)
                return False
            self._notes.append("Reg 成功（附加码 %s）" % ("已提供" if second else "为空"))
            return True

    def guard(self, enable=True, modes=None):
        """加载/确认 dm 盾。只有全部指定盾模式返回 1，才置为已加载。

        安全前提：**未成功注册时绝不调用 DmGuard**。
        实测未注册状态下 DmGuard 会解引用空指针并触发访问违例
        （``access violation reading 0x0``），属于**进程级崩溃**，
        无法用 try/except 兜住。故此处先校验注册状态，不满足则返回结构化错误。
        """
        with self._lock:
            self._ensure_loaded()
            if not enable:
                self._guard_loaded = False
                self._guard_detail = [{"mode": m, "ret": None, "action": "disable-flag-only",
                                       "note": "DM 无卸盾接口，此处仅置服务侧标记"} for m in self.guard_modes]
                return self.status()
            # --- 关键防护：注册状态为“未提供”或“失败”时，禁止触碰 DmGuard ---
            self._ensure_reg_for_native("加载盾")
            modes = list(modes or self.guard_modes)
            self.guard_modes = modes
            detail = []
            all_ok = True
            for m in modes:
                ret = self._be.call("DmGuard", 1, m)
                ok = int(ret) == 1
                all_ok = all_ok and ok
                detail.append({"mode": m, "ret": int(ret), "ok": ok})
            self._guard_detail = detail
            self._guard_loaded = bool(all_ok)
            if not self._guard_loaded:
                raise E.DmMcpError(
                    E.GUARD_NOT_LOADED, "dm 盾加载失败，已拒绝后续内存操作",
                    detail={"modes": detail,
                            "hint": "确认注册码有效（Reg=1）与权限（建议以管理员身份运行）"})
            return self.status()

    def get_last_error(self):
        with self._lock:
            self._ensure_loaded()
            return int(self._be.call("GetLastError"))

    def status(self):
        """返回服务与 DM 的完整状态快照（供 ``dm_status`` 工具与 ``/status`` 端点使用）。"""
        info = {
            "loaded": self._be is not None,
            "is_32bit_host": not BK.IS_64BIT_PY,
            "backend": (self._be.describe() if self._be is not None else None),
            "dm_version": self._version,
            "registered": self._reg_ok,
            # 凭据只回显"是否配置"，绝不回显明文（避免日志/响应泄露注册码）
            "reg_code_configured": bool(self.reg_code),
            "extra_code_configured": bool(self.extra_code),
            "guard_loaded": self._guard_loaded,
            "guard_modes": self.guard_modes,
            "guard_detail": self._guard_detail,
            "bound_hwnd": (hex(self._hwnd) if self._hwnd else None),
            "asm_timeout_ms": self.asm_timeout_ms,
            "notes": self._notes,
            "http_port": self.http_port,
            "window_class": self.window_class,
            "host": HOST.current_host(),
            "auto_bind": self._auto_bind,
        }
        if self._be is not None:
            try:
                info["dm_last_error"] = int(self._be.call("GetLastError"))
            except E.DmMcpError:
                pass
        return info

    # ------------------------------------------------------------ 内部校验
    def _ensure_loaded(self):
        if self._be is None:
            raise E.DmMcpError(E.NOT_LOADED, hint="先调用 dm_load")
        return self._be

    def _ensure_guard(self):
        self._ensure_loaded()
        if not self._guard_loaded:
            raise E.DmMcpError(
                E.GUARD_NOT_LOADED,
                detail={"guard_modes": self.guard_modes, "guard_detail": self._guard_detail})

    def _target(self, hwnd=None):
        """把 hwnd 归一到 int；不传则回落到当前已绑定的句柄。

        ⚠ 必须走 :func:`num` 而不是裸 ``int()``（实测踩坑）：
            ``dm_status`` 把 ``bound_hwnd`` 输出成 **字符串** ``"0x1102b2"``，
            用户/上层脚本很自然地会把这个值复制回来喂给别的工具。
            裸 ``int("0x1102b2")`` 会抛 ``ValueError``，被兜成 ``DM_INTERNAL``
            并附一条 Python 内部异常消息 —— 看起来像"框架崩了"，
            实际只是十六进制字符串没被解析。
            统一用 ``num``（内部先试 ``int(s, 0)``）后，十进制 / 十六进制 /
            ``0x`` 前缀 / 纯数字字符串全都能吃。
        """
        h = hwnd if hwnd is not None else self._hwnd
        h = num(h)
        if not h:
            raise E.DmMcpError(E.NO_TARGET)
        return h

    def _call(self, name, *args):
        return self._be.call(name, *args)

    def _call_checked(self, name, *args):
        """调用并校验 DM 返回值（1=成功，0=失败），失败时带 GetLastError 抛出。"""
        ret = self._call(name, *args)
        if int(ret) == 0:
            try:
                last = self.get_last_error()
            except E.DmMcpError:
                last = None
            raise E.DmMcpError(E.CALL_FAILED, "DM 接口 %s 返回失败" % name,
                               dm_ret=int(ret), dm_last_error=last)
        return ret

    # ------------------------------------------------------------ 目标绑定
    def set_target(self, hwnd):
        # 同样走 num()：接受 "0x1102B2" 这类十六进制字符串，别用裸 int()。
        self._hwnd = num(hwnd)
        return {"bound_hwnd": hex(self._hwnd)}

    def _ensure_reg_for_native(self, what):
        """调用“未注册时会硬崩”的 DM 原生接口前的预检。

        为什么需要（实测教训，2026-09-20）：
            未注册状态下，以下接口会在 DM 内部解引用空指针并触发
            **访问违例（access violation reading 0x0）**，属于**进程级崩溃**，
            Python 层 try/except **完全兜不住** —— 会直接把 MCP 服务打死：
              - ``DmGuard``（加载盾）
              - ``BindWindow`` / ``BindWindowEx``（绑定窗口）
            修复办法不是"优雅处理异常"（来不及），而是**根本不调用**。

        因此凡是要碰这两个族接口的地方，先过这道闸门。
        未注册时抛结构化错误，让调用方拿到可读原因而不是整个进程消失。

        Args:
            what: 用于错误消息的操作名（如 "绑定窗口" / "加载盾"）。
        """
        if self._reg_ok is True:
            return
        if self._reg_ok is None:
            raise E.DmMcpError(
                E.NOT_REGISTERED,
                "未提供注册码，无法%s（已阻止一次会导致进程崩溃的原生调用）" % what,
                hint="设置环境变量 DM_REG_CODE / DM_MCP_REG_CODE，或放置 dm_reg.txt 后重启服务",
                detail={"reg_ok": None})
        raise E.DmMcpError(
            E.NOT_REGISTERED,
            "注册失败（Reg != 1），无法%s（已阻止一次会导致进程崩溃的原生调用）" % what,
            hint="确认注册码与本机机器码匹配；并以管理员身份运行",
            detail={"reg_ok": False})

    def bind_by_hwnd(self, hwnd, display="normal", mouse="normal", keypad="normal",
                     public_desc="normal", mode=0, ex=True):
        """**严格按传入的 hwnd 绑定**：不查找、不复核、不猜测。

        与 :meth:`auto_bind` 的分工（这是本次改造的核心）：

        * ``auto_bind``  —— 没给 hwnd 时的兜底。要依次尝试 FindWindow /
          FindWindowByProcess / 纯标题 / 纯类名 六种候选，再逐个复核类名与标题。
          它的价值是"游戏后启动也能自动接上"，代价是**可能误绑**（实测有第三方工具
          持有标题含"剑灵"的窗口），以及失败时的结论不明确。
        * ``bind_by_hwnd`` —— 调用方**已经知道**要绑哪个窗口（hwnd 由参数传入）。
          此时再去找、再去复核都是多余动作，而且复核反而可能把"用户在工具侧
          自己挑的窗口"误判掉。所以这里直接 BindWindowEx 并如实回报失败原因。

        前置条件（顺序固定，不可颠倒）：
            ① DM 对象已创建 -> ② Reg 已成功 -> ③ 才能绑窗口。
            未注册时 BindWindow 会触发访问违例（进程级崩溃），
            故此处复用 :meth:`_ensure_reg_for_native` 拦住。

        Args:
            hwnd: 目标窗口句柄（十进制 int 或 ``"0x1102B2"`` 形式的字符串）。
            display/mouse/keypad/public_desc/mode: 透传给 BindWindowEx 的模式串。
            ex: ``True`` 用 BindWindowEx（默认），``False`` 用 BindWindow。

        Returns:
            ``{"bound_hwnd": "0x...", "hwnd": int, "source": "explicit-hwnd"}``。

        Raises:
            DmMcpError: ``NO_TARGET``（hwnd 为空）/ ``NOT_REGISTERED``（未注册）
                / ``CALL_FAILED``（DM 返回 0，通常是句柄失效或权限不足）。
        """
        h = num(hwnd)
        if not h:
            raise E.DmMcpError(
                E.NO_TARGET,
                "bind_by_hwnd 需要一个非 0 的窗口句柄，收到 %r" % (hwnd,),
                hint="用 dm_find_window / dm_find_window_by_process 取 hwnd，"
                     "或用启动参数 --hwnd / config.json 的 hwnd 传入")
        out = self.bind_window(h, display=display, mouse=mouse, keypad=keypad,
                               public_desc=public_desc, mode=mode, ex=ex)
        out["hwnd"] = h
        out["source"] = "explicit-hwnd"
        return out

    def bind_window(self, hwnd, display="normal", mouse="normal", keypad="normal",
                    public_desc="normal", mode=0, ex=True):
        # 入口即归一：本方法是公开 API（可直接被 core 调用，不只经 tools 分发），
        # 所以不能假设调用方已经转换过类型。统一 num() 以吃下 "0x.." 字符串。
        hwnd = num(hwnd)
        with self._lock:
            self._ensure_loaded()
            # 关键防护：未注册时 BindWindow(Ex) 会触发访问违例，必须先拦住。
            self._ensure_reg_for_native("绑定窗口")
            if ex:
                self._call_checked("BindWindowEx", hwnd, display, mouse, keypad, public_desc, int(mode))
            else:
                self._call_checked("BindWindow", hwnd, display, mouse, keypad, int(mode))
            self._hwnd = hwnd
            # 本机实测约定：只碰 AsmHwndAsProcessId，**不要动 MemoryHwndAsProcessId**
            # （后者置 1 会让内存函数把 hwnd 当 PID，读取全失败）。
            #
            # ⚠ 但这两个"调优"接口都必须**容忍不存在**（实测教训，2026-09-22）：
            #   dm.dll 7.2607 的 COM 后端**没有** SetAsmHwndAsProcessId，
            #   调用直接返回 DM_NOT_SUPPORTED。而它并不是绑定的必要条件 ——
            #   同一轮实测里，这一步失败后 GetModuleBaseAddr(bnsr.exe) 仍取到
            #   0x140000000、读首 4 字节仍是 0x905A4D（MZ 头校验通过）。
            #   若把它当成致命错误，就会出现"窗口其实已绑好、内存也能读，
            #   但服务报告绑定失败"这种最误导人的状态。
            not_supported = []
            for name, args in (("AsmSetTimeout", (int(self.asm_timeout_ms), 0)),
                               ("SetAsmHwndAsProcessId", (1,))):
                try:
                    self._call(name, *args)
                except E.DmMcpError as exc:
                    not_supported.append({"call": name, "error": exc.code})
            out = {"bound_hwnd": hex(self._hwnd)}
            if not_supported:
                out["optional_failed"] = not_supported
                out["note"] = ("绑定已成功；下列可选调优接口在本 DM 版本不可用，"
                               "已跳过（不影响内存读写）：%s"
                               % ", ".join(x["call"] for x in not_supported))
            return out

    def auto_bind(self, window_class="UnrealWindow", window_title="剑灵", module="bnsr.exe", hwnd=None):
        """启动默认绑定《剑灵》窗口（用户无需再手动 dm_find_window / dm_bind_window）。

        查找顺序（逐个尝试，任一命中即停）：
            1) 显式 hwnd 参数
            2) FindWindow(class, title)
            3) FindWindowByProcess(module, title)
            4) FindWindowByProcess(module, "")
            5) FindWindow("", title)
            6) FindWindow(class, "")

        语义约束：
            - 只做“查找 + 绑定 + 记录状态”，不隐式触发内存读写；
            - 本方法**不抛异常**（“游戏未启动”属可恢复情况，不应阻断服务启动），
              结果记录在 self._auto_bind 并随 dm_status 返回，字段 error / hint 说明原因；
            - 绑定成功但盾未加载时给出 warning（内存接口仍会被 _ensure_guard 拒绝）。

        严格性约束（重要）：
            第 4~6 步属于**宽松回退**（只给进程名或只给类名/标题），存在误绑到同名类或
            同名标题的其他窗口的风险。因此命中后一律调用 :meth:`_verify_target_window`
            复核“类名 == window_class 且标题包含 window_title”，复核不通过则**继续尝试**
            后续候选，绝不轻易 BindWindowEx。全部候选都复核失败时返回明确错误而非静默误绑。
        """
        with self._lock:
            # 先归一：hwnd 可能以 "0x1102B2" 字符串形式传入（启动参数/配置常见）。
            hwnd = num(hwnd)
            info = {
                "attempted": True,
                "time": time.strftime("%Y-%m-%d %H:%M:%S"),
                "window_class": window_class,
                "window_title": window_title,
                "module": module,
                "ok": False,
                "source": None,
                "hwnd": 0,
                "bound_hwnd": None,
                "guard_loaded": self._guard_loaded,
                "steps": [],
                "error": None,
                "hint": None,
            }
            if self._be is None:
                info["error"] = E.NOT_LOADED
                info["hint"] = ("DM 尚未加载，跳过启动绑定；dm_load 成功后调用 dm_find_window + dm_bind_window 手动绑定")
                self._auto_bind = info
                return info

            attempts = []
            if hwnd:
                # 显式 hwnd 视为调用方已确认目标，跳过类名/标题复核
                attempts.append(("explicit-hwnd(%s)" % hex(int(hwnd)),
                                 lambda: {"hwnd": int(hwnd)}, False))
            attempts.append(("FindWindow(class=%s, title=%s)" % (window_class, window_title),
                             lambda: self.find_window(window_class, window_title), True))
            if module:
                attempts.append(("FindWindowByProcess(process=%s, title=%s)" % (module, window_title),
                                 lambda: self.find_window_by_process(module, window_title), True))
                attempts.append(("FindWindowByProcess(process=%s, title='')" % module,
                                 lambda: self.find_window_by_process(module, ""), True))
            if window_title:
                attempts.append(("FindWindow(title=%s)" % window_title,
                                 lambda: self.find_window("", window_title), True))
            if window_class:
                attempts.append(("FindWindow(class=%s)" % window_class,
                                 lambda: self.find_window(window_class, ""), True))

            found = 0
            for label, fn, need_verify in attempts:
                try:
                    out = fn() or {}
                except E.DmMcpError as exc:
                    info["steps"].append({"try": label, "ok": False, "error": exc.code})
                    continue
                h = num(out.get("hwnd"))
                if not h:
                    info["steps"].append({"try": label, "ok": False, "hwnd": 0})
                    continue
                if need_verify:
                    verified, detail = self._verify_target_window(h, window_class, window_title)
                    info["steps"].append({"try": label, "ok": bool(verified), "hwnd": h,
                                          "verify": detail})
                    if not verified:
                        continue
                else:
                    info["steps"].append({"try": label, "ok": True, "hwnd": h,
                                          "verify": "explicit-hwnd（跳过复核）"})
                found = h
                info["source"] = label
                break

            info["hwnd"] = found
            if not found:
                info["error"] = E.NO_TARGET
                info["hint"] = ("未找到通过复核的《剑灵》窗口（要求 类名 == %r 且标题包含 %r，进程 %s）："
                                "请确认游戏已运行；游戏启动后可再次调用 dm_auto_bind 重试，"
                                "或用 dm_find_window + dm_bind_window 手动绑定"
                                % (window_class, window_title, module))
                self._auto_bind = info
                return info

            try:
                self.bind_window(found)
            except E.DmMcpError as exc:
                info["error"] = exc.code
                info["bind_error"] = exc.to_dict()
                if exc.code == E.NOT_REGISTERED:
                    # 未注册导致绑定被主动阻止：这不是"窗口找不到"，提示要准确。
                    info["hint"] = ("已找到窗口 %s，但未注册无法绑定（未注册时 BindWindow 会硬崩，已阻止）。"
                                    "请设置环境变量 DM_REG_CODE / DM_MCP_REG_CODE，或放置 dm_reg.txt 后重启服务"
                                    % hex(found))
                else:
                    info["hint"] = ("已找到窗口 %s 但绑定失败；可调用 dm_bind_window 重试"
                                    "（必要时以管理员身份运行）" % hex(found))
                self._auto_bind = info
                return info

            info["ok"] = True
            info["bound_hwnd"] = hex(found)
            info["guard_loaded"] = self._guard_loaded
            if not self._guard_loaded:
                info["warning"] = ("窗口已绑定，但 dm 盾未加载：内存读写/搜索接口仍会被拒绝；"
                                   "确认注册码与管理员权限后调用 dm_guard 重试")
            self._auto_bind = info
            return info

    def _window_class(self, hwnd):
        """取窗口类名，兼容不同 DM 版本的方法命名。

        为什么需要兼容层（实测教训）：
            本机 DM 7.2607 的 **COM 接口里没有 `GetClassName`**，
            类名方法叫 **`GetWindowClass`**；调用 `GetClassName` 会得到
            ``DM_NOT_SUPPORTED``。而 dll 后端更彻底 —— dm.dll 只导出 4 个标准
            COM 入口（DllGetClassObject 等），**根本不提供扁平 C 导出**，
            所以 `--backend dll` 在本版本上必然失败，COM 是唯一可用后端。

            这个差异很致命：类名校验正是"防止误绑同名窗口"的最后一道闸门。
            若类名读不到，auto_bind 就只能靠标题模糊匹配 —— 而实测存在
            第三方工具（剑灵小助手）持有标题含"剑灵"的窗口，
            误绑后会读到垃圾数据且极难排查。

        因此这里依次尝试 `GetWindowClass` → `GetClassName`，
        而不是写死单一名字。
        """
        last_exc = None
        for name in ("GetWindowClass", "GetClassName"):
            try:
                return str(self._call(name, self._target(hwnd)) or "")
            except E.DmMcpError as exc:
                last_exc = exc
                continue
        raise last_exc

    def _verify_target_window(self, hwnd, window_class, window_title):
        """复核候选 hwnd 是否真的是目标窗口。

        规则（与既有逆向结论一致，且**不做模糊匹配**）：
            - 窗口类名必须 **完全等于** ``window_class``（大小写敏感，
              因为 ``UnrealWindow`` 是该引擎的固定类名）；
            - 若给了 ``window_title``，则 ``GetWindowTitle(hwnd)`` 必须 **包含** 该标题
              （既有结论：标题含《剑灵》带书名号，故用包含而不是相等，以兼容标题里的
              版本号 / 区服后缀）。

        注意：取类名走 :meth:`_window_class`（兼容 GetWindowClass / GetClassName）。

        Args:
            hwnd: 候选窗口句柄。
            window_class: 期望的窗口类名；空字符串表示不校验类名。
            window_title: 期望的标题关键字；空字符串表示不校验标题。

        Returns:
            ``(ok, detail)``：``ok`` 为是否通过复核；``detail`` 为人类可读的复核说明
            （含实际读到的类名/标题），便于在 ``auto_bind.steps`` 里定位为何被拒绝。
        """
        actual_class = ""
        actual_title = ""
        try:
            actual_class = self._window_class(hwnd)
        except E.DmMcpError as exc:
            return False, "取窗口类名失败：%s" % exc.code
        try:
            actual_title = str(self._call("GetWindowTitle", hwnd) or "")
        except E.DmMcpError as exc:
            return False, "GetWindowTitle 失败：%s" % exc.code

        if window_class and actual_class != window_class:
            return False, "类名不匹配：期望 %r，实际 %r" % (window_class, actual_class)
        if window_title and window_title not in actual_title:
            return False, "标题不含关键字：期望含 %r，实际 %r" % (window_title, actual_title)
        return True, "类名=%r 标题=%r" % (actual_class, actual_title)

    def unbind_window(self):
        with self._lock:
            self._ensure_loaded()
            ret = self._call("UnBindWindow")
            self._hwnd = None
            return {"unbind_ret": int(ret)}

    def set_asm_hwnd_as_process_id(self, enable=1):
        with self._lock:
            self._ensure_loaded()
            return {"ret": int(self._call("SetAsmHwndAsProcessId", int(enable)))}

    def set_memory_hwnd_as_process_id(self, enable=0):
        """⚠ 本机实测：置 1 会让内存函数把 hwnd 当进程 ID，导致读取全失败，默认保持 0。"""
        with self._lock:
            self._ensure_loaded()
            return {"ret": int(self._call("SetMemoryHwndAsProcessId", int(enable))),
                    "warning": "本机实测建议保持 0（仅用 SetAsmHwndAsProcessId(1)）"}

    # ------------------------------------------------------------ 窗口/进程
    def find_window(self, class_name="", title=""):
        self._ensure_loaded()
        hwnd = num(self._call("FindWindow", class_name, title))
        out = {"hwnd": hwnd, "class_name": class_name, "title": title}
        if not hwnd:
            out["hint"] = "未找到：确认目标进程已运行；或改用 dm_find_window_by_process / dm_enum_window"
        return out

    def find_window_by_process(self, process_name, title=""):
        self._ensure_loaded()
        hwnd = num(self._call("FindWindowByProcess", process_name, title))
        out = {"hwnd": hwnd, "process_name": process_name, "title": title}
        if not hwnd:
            out["hint"] = "未找到：进程名须与任务管理器一致（如 BNSR.exe）；title 可留空"
        return out

    def get_process_id(self, hwnd=None):
        self._ensure_loaded()
        return {"pid": num(self._call("GetWindowProcessId", self._target(hwnd)))}

    def get_module_base_addr(self, module_name, hwnd=None):
        """取模块基址。

        DM 对 64 位目标可能返回 64 位整数，也可能只提供字符串形式（GetModuleBaseAddrEx），
        因此按 GetModuleBaseAddr -> GetModuleBaseAddrEx 依次尝试，并回传每次尝试的原始值，
        便于调用方核对，而不是猜。
        """
        self._ensure_loaded()
        h = self._target(hwnd)
        tried = {}
        for method in ("GetModuleBaseAddr", "GetModuleBaseAddrEx"):
            try:
                raw = self._call(method, h, module_name)
            except E.DmMcpError as exc:
                tried[method] = {"error": exc.code}
                continue
            val = num(raw)
            tried[method] = {"raw": raw, "value": val, "value_hex": (hex(val) if val else None)}
            if val >= 0x10000:  # 0 或过小值视为该接口不可用/被截断
                return {"base": val, "base_hex": hex(val), "module": module_name,
                        "source": method, "tried": tried}
        return {"base": 0, "base_hex": None, "module": module_name, "source": None, "tried": tried,
                "hint": "两个接口均未取到有效基址：确认模块名（如 bnsr.exe / BNSR.exe）与窗口绑定状态"}

    def get_window_title(self, hwnd=None):
        self._ensure_loaded()
        return {"title": self._call("GetWindowTitle", self._target(hwnd))}

    def get_class_name(self, hwnd=None):
        """取窗口类名（兼容 GetWindowClass / GetClassName，见 :meth:`_window_class`）。"""
        self._ensure_loaded()
        return {"class_name": self._window_class(hwnd)}

    def get_window_rect(self, hwnd=None):
        self._ensure_loaded()
        r = self._call("GetWindowRect", self._target(hwnd))
        # DM 返回 "x1,y1,x2,y2" 字符串
        try:
            parts = [int(x) for x in str(r).replace("|", ",").split(",")[:4]]
        except ValueError:
            parts = []
        return {"rect_raw": r, "rect": parts}

    def enum_window(self, parent=0, title="", class_name=""):
        self._ensure_loaded()
        raw = self._call("EnumWindow", num(parent), title, class_name, 1)
        # DM 返回 "hwnd1,hwnd2,..."（十进制）。这里用 num() 逐个归一而不是
        # isdigit() 过滤：万一某个版本回十六进制，"1234,0x1A2B" 这种混合串
        # 会被 isdigit() 静默丢掉一半句柄，比解析成 0 更难排查。
        items = [num(x) for x in str(raw).split(",") if str(x).strip()]
        return {"hwnds": [x for x in items if x], "raw": raw}

    # ------------------------------------------------------------ 内存读
    def _read_float_like(self, method, addr, hwnd=None):
        raw = self._call(method, self._target(hwnd), addr_str(addr))
        try:
            return float(raw)
        except (TypeError, ValueError):
            raise E.DmMcpError(E.CALL_FAILED, "%s 返回非数值" % method, detail={"raw": raw})

    def read_int(self, addr, type=3, hwnd=None):
        self._ensure_guard()
        raw = self._call("ReadInt", self._target(hwnd), addr_str(addr), int(type))
        return {"value": num(raw), "raw": raw}

    def read_float(self, addr, hwnd=None):
        self._ensure_guard()
        return {"value": self._read_float_like("ReadFloat", addr, hwnd)}

    def read_double(self, addr, hwnd=None):
        self._ensure_guard()
        return {"value": self._read_float_like("ReadDouble", addr, hwnd)}

    def read_string(self, addr, length=32, type=0, hwnd=None):
        self._ensure_guard()
        s = self._call("ReadString", self._target(hwnd), addr_str(addr), int(type), int(length))
        return {"value": s}

    def read_raw_bytes(self, addr, length, hwnd=None):
        """稳定读字节：按 8/4/2/1 宽度分块用 ReadInt 拼接。

        本机实测：DM 原生 ReadDataAddr 对 64 位大地址不稳定（返回空），故默认走本函数。
        """
        self._ensure_guard()
        h = self._target(hwnd)
        base = num(addr)
        out = bytearray()
        off = 0
        while off < length:
            remain = length - off
            for width in (8, 4, 2, 1):
                if remain >= width:
                    t = TYPE_BY_WIDTH[width]
                    val = num(self._call("ReadInt", h, addr_str(base + off), t))
                    out += (val & ((1 << (width * 8)) - 1)).to_bytes(width, "little")
                    off += width
                    break
        return bytes(out)

    def read_data(self, addr, length=16, encoding="hex", hwnd=None, native=False):
        self._ensure_guard()
        if native:
            raw = self._call("ReadDataAddr", self._target(hwnd), addr_str(addr), int(length))
            text = str(raw or "").replace(" ", "")
            try:
                data = binascii.unhexlify(text) if text else b""
            except (binascii.Error, ValueError) as exc:
                raise E.DmMcpError(E.CALL_FAILED, "ReadDataAddr 返回非 hex 数据",
                                   detail={"raw": raw, "reason": str(exc)})
            note = "native(ReadDataAddr)"
        else:
            data = self.read_raw_bytes(addr, int(length), hwnd)
            note = "chunked(ReadInt 8/4/2/1)"
        if encoding == "base64":
            text = base64.b64encode(data).decode("ascii")
        else:
            text = " ".join("%02X" % b for b in data)
        return {"data": text, "length": len(data), "encoding": encoding, "method": note}

    # ------------------------------------------------------------ 内存写
    def write_int(self, addr, value, type=0, hwnd=None):
        self._ensure_guard()
        # DM 原生签名：WriteInt(hwnd, addr, type, v) —— type 在 value 之前
        self._call_checked("WriteInt", self._target(hwnd), addr_str(addr), int(type), str(int(value)))
        return {"ok_write": True, "addr": addr_str(addr), "value": int(value), "type": int(type)}

    def write_float(self, addr, value, hwnd=None):
        self._ensure_guard()
        self._call_checked("WriteFloat", self._target(hwnd), addr_str(addr), float(value))
        return {"ok_write": True, "addr": addr_str(addr), "value": float(value)}

    def write_double(self, addr, value, hwnd=None):
        self._ensure_guard()
        self._call_checked("WriteDouble", self._target(hwnd), addr_str(addr), float(value))
        return {"ok_write": True, "addr": addr_str(addr), "value": float(value)}

    def write_string(self, addr, value, type=0, hwnd=None):
        self._ensure_guard()
        # DM 原生签名：WriteString(hwnd, addr, type, v)
        self._call_checked("WriteString", self._target(hwnd), addr_str(addr), int(type), value)
        return {"ok_write": True, "addr": addr_str(addr), "length": len(value)}

    def write_raw_bytes(self, addr, data, hwnd=None):
        """按 8/4/2/1 分块写字节（WriteInt type=3/0/1/2）。"""
        self._ensure_guard()
        h = self._target(hwnd)
        base = num(addr)
        off = 0
        n = 0
        while off < len(data):
            remain = len(data) - off
            for width in (8, 4, 2, 1):
                if remain >= width:
                    chunk = data[off:off + width]
                    val = int.from_bytes(chunk, "little")
                    self._call_checked("WriteInt", h, addr_str(base + off), TYPE_BY_WIDTH[width], str(val))
                    off += width
                    n += 1
                    break
        return {"ok_write": True, "addr": addr_str(addr), "bytes": len(data), "chunks": n}

    def write_data(self, addr, data, encoding="hex", hwnd=None):
        self._ensure_guard()
        if encoding == "base64":
            raw = base64.b64decode(data)
        else:
            raw = binascii.unhexlify(str(data).replace(" ", "").replace("\n", ""))
        return self.write_raw_bytes(addr, raw, hwnd)

    # ------------------------------------------------------------ 内存搜索
    # ---- 真实签名（来源：dm.dll 类型库，权威） ----
    #   FindInt(hwnd, addr_range, int_value_min, int_value_max, type)                  5 参
    #   FindFloat(hwnd, addr_range, float_value_min, float_value_max)                  4 参
    #   FindDouble(hwnd, addr_range, double_value_min, double_value_max)                4 参
    #   FindString(hwnd, addr_range, string_value, type)                                4 参
    #   FindData(hwnd, addr_range, data)                                                3 参
    #   *Ex 变体在末尾追加 step / multi_thread / mode
    #
    # ⚠️ 与直觉不同的两点（早期实现的 bug 来源）：
    #   1) FindInt 没有 "step" 参数 —— 第 4 个位置是 **int_value_max**（取值上界），
    #      早期实现把 step 传到那里，等于把"搜索步长"当成了"数值上界"，
    #      搜索结果会静默错误（步长>1 时尤其明显）。
    #   2) FindString/FindData 没有 step；FindString 的第 4 参才是 type。
    #
    # 为了兼容原有工具 schema（调用方可能在传 step），这里采用"**降级而非报错**"策略：
    # 需要 step 时自动改用 *Ex 变体（它们才有 step 参数）。
    def _find(self, fn, addr_range, values, hwnd=None):
        """统一的 Find* 调用出口。

        **所有数值参数都必须以字符串（BSTR）传给 DM** —— 这是实测结论：
            FindInt(hwnd, range, 23117, 23117, 0)     -> DISP_E_TYPEMISMATCH (-2147352571) ❌
            FindInt(hwnd, range, "23117", "23117", 0) -> 正常                       ✅

        DM 的类型库里这些参数声明为 BSTR。传 Python int 时，
        IDispatch 会在**参数类型校验**阶段就拒绝（hresult = DISP_E_TYPEMISMATCH），
        **根本不会进入 DM 的执行体**，因此 `GetLastError` 也不会有 DM 错误码可看。
        这类失败很容易被误判成"搜索功能坏了"。

        （`core.call` 层的假后端之所以"看起来都能传"，是因为 `_make_variant`
        对 int 会兜底成 VT_I4；但真实 IDispatch 会严格按签名校验，兜不住。）
        """
        self._ensure_guard()
        h = self._target(hwnd)
        if isinstance(values, (list, tuple)):
            vals = ["" if v is None else str(v) for v in values]
        else:
            vals = [str(values)]
        # 地址范围也必须是 hex 字符串，十进制会被 DM 静默忽略（搜不到任何结果）。
        args = [h, addr_str_range(addr_range)] + vals
        raw = self._call(fn, *args)
        return {"addresses_raw": raw, "method": fn,
                "addresses": [a for a in str(raw).split(",") if a.strip()]}

    def find_int(self, addr_range, value_min, value_max=None, type=0, step=1, hwnd=None,
                 multi_thread=0, mode=0):
        """搜索整数：``FindInt(hwnd, addr_range, min, max, type)``。

        Args:
            addr_range: 地址范围，如 ``"0x140000000-0x150000000"``。
            value_min: 数值下界；只查单值时与 ``value_max`` 相同即可。
            value_max: 数值上界；``None`` 时取 ``value_min``（等价于精确匹配）。
            type: 0=i32 1=i16 2=i8 3=i64。
            step: 搜索步长。**step != 1 时会自动改用 FindIntEx**
                  （FindInt 本体没有 step 参数）。
        """
        if step and int(step) != 1:
            return self.find_int_ex(addr_range, value_min, value_max, type=type, step=step,
                                    hwnd=hwnd, multi_thread=multi_thread, mode=mode)
        return self._find("FindInt", addr_range,
                          [value_min, value_min if value_max is None else value_max, str(int(type))],
                          hwnd=hwnd)

    def find_int_ex(self, addr_range, value_min, value_max=None, type=0, step=1,
                    multi_thread=0, mode=0, hwnd=None):
        """搜索整数（带步长/多线程）：``FindIntEx(hwnd, range, min, max, type, step, mt, mode)``。"""
        self._ensure_guard()
        h = self._target(hwnd)
        raw = self._call("FindIntEx", h, addr_str_range(addr_range),
                         str(value_min), str(value_min if value_max is None else value_max),
                         str(int(type)), str(int(step)), str(int(multi_thread)), str(int(mode)))
        return {"addresses_raw": raw, "method": "FindIntEx",
                "addresses": [a for a in str(raw).split(",") if a.strip()]}

    def find_float(self, addr_range, value_min, value_max=None, step=1.0, hwnd=None,
                   multi_thread=0, mode=0):
        """搜索 float：``FindFloat(hwnd, addr_range, min, max)``（无 step；step!=1 时走 FindFloatEx）。"""
        if step and float(step) != 1.0:
            return self.find_float_ex(addr_range, value_min, value_max, step=step,
                                      hwnd=hwnd, multi_thread=multi_thread, mode=mode)
        return self._find("FindFloat", addr_range,
                          [value_min, value_min if value_max is None else value_max], hwnd=hwnd)

    def find_float_ex(self, addr_range, value_min, value_max=None, step=1.0,
                      multi_thread=0, mode=0, hwnd=None):
        self._ensure_guard()
        h = self._target(hwnd)
        raw = self._call("FindFloatEx", h, addr_str_range(addr_range),
                         str(value_min), str(value_min if value_max is None else value_max),
                         str(float(step)), str(int(multi_thread)), str(int(mode)))
        return {"addresses_raw": raw, "method": "FindFloatEx",
                "addresses": [a for a in str(raw).split(",") if a.strip()]}

    def find_double(self, addr_range, value_min, value_max=None, step=1.0, hwnd=None,
                    multi_thread=0, mode=0):
        """搜索 double：``FindDouble(hwnd, addr_range, min, max)``。"""
        if step and float(step) != 1.0:
            return self.find_double_ex(addr_range, value_min, value_max, step=step,
                                       hwnd=hwnd, multi_thread=multi_thread, mode=mode)
        return self._find("FindDouble", addr_range,
                          [value_min, value_min if value_max is None else value_max], hwnd=hwnd)

    def find_double_ex(self, addr_range, value_min, value_max=None, step=1.0,
                       multi_thread=0, mode=0, hwnd=None):
        self._ensure_guard()
        h = self._target(hwnd)
        raw = self._call("FindDoubleEx", h, addr_str_range(addr_range),
                         str(value_min), str(value_min if value_max is None else value_max),
                         str(float(step)), str(int(multi_thread)), str(int(mode)))
        return {"addresses_raw": raw, "method": "FindDoubleEx",
                "addresses": [a for a in str(raw).split(",") if a.strip()]}

    def find_string(self, addr_range, value, type=0, step=1, hwnd=None,
                    multi_thread=0, mode=0):
        """搜索字符串：``FindString(hwnd, addr_range, string_value, type)``（无 step）。"""
        if step and int(step) != 1:
            return self.find_string_ex(addr_range, value, type=type, step=step,
                                       hwnd=hwnd, multi_thread=multi_thread, mode=mode)
        return self._find("FindString", addr_range, [value, str(int(type))], hwnd=hwnd)

    def find_string_ex(self, addr_range, value, type=0, step=1,
                       multi_thread=0, mode=0, hwnd=None):
        self._ensure_guard()
        h = self._target(hwnd)
        raw = self._call("FindStringEx", h, addr_str_range(addr_range), value,
                         str(int(type)), str(int(step)), str(int(multi_thread)), str(int(mode)))
        return {"addresses_raw": raw, "method": "FindStringEx",
                "addresses": [a for a in str(raw).split(",") if a.strip()]}

    def find_data(self, addr_range, data, step=1, hwnd=None, multi_thread=0, mode=0):
        """搜索字节序列：``FindData(hwnd, addr_range, data)``（无 step）。"""
        if step and int(step) != 1:
            return self.find_data_ex(addr_range, data, step=step,
                                     hwnd=hwnd, multi_thread=multi_thread, mode=mode)
        return self._find("FindData", addr_range, [data], hwnd=hwnd)

    def find_data_ex(self, addr_range, data, step=1, multi_thread=0, mode=0, hwnd=None):
        self._ensure_guard()
        h = self._target(hwnd)
        raw = self._call("FindDataEx", h, addr_str_range(addr_range), data,
                         str(int(step)), str(int(multi_thread)), str(int(mode)))
        return {"addresses_raw": raw, "method": "FindDataEx",
                "addresses": [a for a in str(raw).split(",") if a.strip()]}

    # ------------------------------------------------------------ 内存操作
    # ---- 真实的 DM 接口签名（来源：dm.dll 自带类型库 IDispatch::GetTypeInfo，权威） ----
    #   VirtualAllocEx(hwnd, addr, size, type)                       4 参，**没有 protect**
    #   VirtualProtectEx(hwnd, addr, size, type, old_protect)        5 参，末位是"旧保护属性"输出位
    #   VirtualFreeEx(hwnd, addr)                                    2 参，**没有 size/type**
    # 之所以要在这里写清楚：早期实现按"Windows API 同名函数"的直觉传参
    #   （VirtualAllocEx 补 protect、VirtualFreeEx 传 size+type），
    # COM 层参数个数不匹配 -> IDispatch::Invoke 失败 -> DM_CALL_FAILED。
    # 这类错误在 Windows API 文档里查不到，只能以 DM 类型库为准。
    def virtual_alloc_ex(self, size, addr=0, type=1, hwnd=None):
        """在目标进程申请内存：``VirtualAllocEx(hwnd, addr, size, type)``。

        Args:
            size: 字节数。
            addr: 期望基址；``0`` 表示由系统选择。
            type: ``0``=32 位模式（返回 32 位地址空间）
                  ``1``=64 位模式（**剑灵等 64 位目标必须用 1**）。
            hwnd: 目标窗口；``None`` 用已绑定窗口。

        Note:
            DM 的 ``VirtualAllocEx`` **只有 4 个参数、没有 protect**，
            保护属性固定为可读写。需要改为只读/可执行请用 ``virtual_protect_ex``。
        """
        self._ensure_guard()
        ret = num(self._call("VirtualAllocEx", self._target(hwnd), num(addr), int(size), int(type)))
        if ret == 0:
            raise E.DmMcpError(E.CALL_FAILED, "VirtualAllocEx 返回 0",
                               dm_ret=0, dm_last_error=self.get_last_error(),
                               detail={"hint": "64 位目标进程需传 type=1；addr 请传 0 让系统选择"})
        return {"address": ret, "address_hex": hex(ret), "size": int(size), "type": int(type)}

    def virtual_protect_ex(self, addr, size, type=1, protect=0x40, hwnd=None):
        """修改目标进程内存保护属性：``VirtualProtectEx(hwnd, addr, size, type, old_protect)``。

        第 5 个参数在 DM 里名为 ``old_protect``：传进去的是"期望的新保护属性"，
        返回的是**改动前的旧属性**（不是成功与否；0 也可能是合法的旧属性值）。

        Args:
            size: 字节数。
            type: ``0``=32 位模式 ``1``=64 位模式。
            protect: 新保护属性，如 ``0x40``=PAGE_EXECUTE_READWRITE、``0x04``=PAGE_READWRITE、
                     ``0x20``=PAGE_EXECUTE_READ。
        """
        self._ensure_guard()
        ret = num(self._call("VirtualProtectEx", self._target(hwnd), num(addr), int(size),
                             int(type), int(protect)))
        return {"old_protect": ret, "old_protect_hex": hex(ret), "addr": addr_str(addr),
                "size": int(size), "type": int(type), "new_protect": int(protect)}

    def virtual_free_ex(self, addr, hwnd=None):
        """释放目标进程内存：``VirtualFreeEx(hwnd, addr)`` —— **只有 2 个参数**。

        DM 的 ``VirtualFreeEx`` 不接受 size / type（与 Windows 同名 API 不同），
        地址必须是 ``VirtualAllocEx`` 返回的基址，且整个区域一次性释放。
        """
        self._ensure_guard()
        ret = num(self._call("VirtualFreeEx", self._target(hwnd), num(addr)))
        return {"ret": ret, "addr": addr_str(addr), "ok_free": ret != 0}

    # ------------------------------------------------------------ 输入（辅助）
    def key_down(self, vk, hwnd=None):
        self._ensure_loaded()
        return {"ret": int(self._call("KeyDown", self._target(hwnd), int(vk)))}

    def key_up(self, vk, hwnd=None):
        self._ensure_loaded()
        return {"ret": int(self._call("KeyUp", self._target(hwnd), int(vk)))}

    def key_press(self, vk, hwnd=None):
        self._ensure_loaded()
        return {"ret": int(self._call("KeyPress", self._target(hwnd), int(vk)))}

    def move_to(self, x, y):
        self._ensure_loaded()
        return {"ret": int(self._call("MoveTo", int(x), int(y)))}

    def left_click(self):
        self._ensure_loaded()
        return {"ret": int(self._call("LeftClick"))}

    def set_keypad_delay(self, press_delay, release_delay):
        self._ensure_loaded()
        return {"ret": int(self._call("SetKeypadDelay", str(press_delay), str(release_delay)))}

    # ------------------------------------------------------------ 通用兜底
    def raw_call(self, name, args=None):
        """直接调用 DM 接口（兜底覆盖未显式封装的 API）。

        ⚠ 若目标接口属于内存类，请先用 dm_guard 加载盾；本通用入口同样强制校验盾状态，
           白名单外的“明显内存类”接口名（Read*/Write*/Find*/Virtual*）一律拦截。
        """
        self._ensure_loaded()
        name = str(name)
        args = list(args or [])
        low = name.lower()
        if low.startswith(("read", "write", "find", "virtual")):
            self._ensure_guard()
        coerce = []
        for a in args:
            if isinstance(a, str):
                coerce.append(a)
            elif isinstance(a, float):
                coerce.append(a)
            else:
                coerce.append(int(a))
        ret = self._call(name, *coerce)
        return {"method": name, "ret": ret}

    def close(self):
        with self._lock:
            self._be = None
            self._guard_loaded = False
