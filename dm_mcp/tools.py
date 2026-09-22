# -*- coding: utf-8 -*-
"""工具注册表：MCP tools/list 与 tools/call 的唯一事实来源。

每个工具声明：
    name        工具名（建议统一 dm_ 前缀）
    description 中文说明（含关键实测约定）
    inputSchema JSON Schema
    requires    前置条件：'loaded' | 'guard' | 'target'（服务侧强校验，缺失即拒绝）
"""

from . import errors as E


# ---------------------------------------------------------------- 帮助函数
def _addr(v):
    """地址归一化：整数 -> 0x 十六进制字符串；字符串原样保留（支持 CE 风格表达式）。"""
    if v is None:
        return None
    if isinstance(v, bool):
        return "0x%X" % int(v)
    if isinstance(v, int):
        return "0x%X" % v
    return str(v)


def _u64(v):
    """把句柄/地址统一成 int，兼容 int / "0x140000000" / "5368709120"（CE 风格也支持）。

    注意不能用 ``int(v)`` 直接转：十六进制字符串（最常见，如 "0x140000000"）
    会抛 ``ValueError: invalid literal for int() with base 10``。
    必须用 ``int(v, 0)`` 让 Python 自动识别 0x / 0o / 0b 前缀。
    """
    if v is None:
        return None
    if isinstance(v, bool):
        return int(v)
    if isinstance(v, int):
        return v
    s = str(v).strip()
    if not s:
        return None
    return int(s, 0)


def _num_s(v):
    """数值归一化为字符串，供 FindFloat/FindDouble 的 min/max 使用。

    为什么不直接 int()：float/double 的搜索值是**浮点数**，
    用 int() 截断会把 ``1.5`` 变成 ``1``，搜索目标就变了。
    这里统一转成 ``str``，让 DM 按 float/double 语义解析。
    """
    if v is None:
        return None
    if isinstance(v, bool):
        return str(int(v))
    if isinstance(v, str):
        return v
    return repr(float(v)) if isinstance(v, float) else str(v)


def _int_s(v):
    """整数搜索值归一化为**十进制字符串**，供 FindInt 的 min/max 使用。

    为什么不能用 ``_addr``：``_addr`` 输出的是 ``"0x..."`` 十六进制字面量，
    那是给**地址**用的。DM 的 ``FindInt`` 的 min/max 是**搜索数值**，
    用 ``"0x"`` 前缀会被 DM 当成非法数字（或解析成 0），搜索目标就错了。

    也不能叫 ``_num_s``：那是给 float/double 用的，会走 ``float()`` 路径，
    对 int64/uint64 大数（如 ``0x1122334455667788``）会丢精度。
    这里统一转十进制字符串，保留完整精度。
    """
    if v is None:
        return None
    if isinstance(v, bool):
        return str(int(v))
    if isinstance(v, str):
        s = v.strip()
        if not s:
            return None
        # 支持用户直接写 "0x1000" / "1000" 两种风格，统一转成十进制字面量
        return str(int(s, 0))
    return str(int(v))


def _tool(name, desc, props, required=None):
    return {
        "name": name,
        "description": desc,
        "inputSchema": {
            "type": "object",
            "properties": props or {},
            "required": required or [],
        },
    }


ADDR = {"type": "string", "description": "地址，支持 CE 风格：'0x140000000' / '4DA678' / 'bnsr+0x1234567' / '[0x1234]+8'（模块名可写 bnsr.exe）"}
HWND = {"type": "string", "description": "窗口句柄（十进制或 0x 十六进制）。省略则用当前已绑定窗口"}


TOOLS = [
    # ================= 生命周期 / 状态 =================
    _tool("dm_load", "加载 dm.dll（或创建 dm.dmsoft COM 对象）并可选立即加载 dm 盾。常驻进程只需在会话开始时调用一次。",
          {"dll_path": {"type": "string", "description": "dm.dll 绝对路径；省略则自动探测（参数/环境变量/常见位置/注册表）"},
           "reg_code": {"type": "string", "description": "DM 注册码（推荐写在 config.json，不要硬编码在脚本里）"},
           "backend": {"type": "string", "enum": ["auto", "dll", "com"], "description": "后端选择：默认 auto（先 COM dm.dmsoft，失败回退 ctypes 直调 dm.dll 导出）"},
           "guard": {"type": "boolean", "description": "加载成功后是否立即加载 dm 盾，默认 true"}}),
    _tool("dm_auto_bind", "★ 自动查找并绑定《剑灵》窗口（class=UnrealWindow、标题含“剑灵”、进程 bnsr.exe）。启动时默认已自动执行一次；游戏后启动或换窗口时可手动调用，无需再组合 dm_find_window + dm_bind_window。",
          {"window_class": {"type": "string", "default": "UnrealWindow"},
           "window_title": {"type": "string", "default": "剑灵"},
           "module": {"type": "string", "description": "目标进程名，如 bnsr.exe", "default": "bnsr.exe"},
           "hwnd": HWND}),
    _tool("dm_status", "查看服务与 DM 状态：宿主位数（host.bits / host.exe / 是否由 64 位自动重拉）、后端、DM 版本、注册状态、盾状态、已绑定窗口、启动默认绑定结果（auto_bind）、最近错误。", {}),
    _tool("dm_reg", "调用 DM Reg 注册（注册码有效时返回 1）。注意：Reg 成功是 DmGuard 生效的前提之一。",
          {"code": {"type": "string"}}, ["code"]),
    _tool("dm_guard", "★ 加载 dm 盾（DmGuard）。只有全部盾模式返回 1 才算加载成功；未加载盾时所有内存读写/搜索/内存操作接口都会被拒绝。",
          {"modes": {"type": "array", "items": {"type": "string"},
                     "description": "盾模式列表，默认 [\"memory2\",\"b3\"]（本机实测可用）"},
           "enable": {"type": "boolean", "description": "false 仅置服务侧标记（DM 无卸盾接口）"}}),
    _tool("dm_get_last_error", "读取 DM 内部错误码（GetLastError）。0 表示无错误。", {}),
    _tool("dm_version", "读取 DM 版本（Ver）。", {}),
    _tool("dm_set_path", "设置 DM 资源目录（SetPath），一般指向 dm.dll 所在目录。",
          {"path": {"type": "string"}}, ["path"]),
    _tool("dm_raw_call", "通用兜底：直接调用任意 DM 接口（未显式封装的 API 走这里）。名称以 Read/Write/Find/Virtual 开头时强制校验盾状态。",
          {"method": {"type": "string", "description": "DM 接口名，如 'GetMachineCode'、'SetWindowSize'"},
           "args": {"type": "array", "items": {"type": ["string", "integer", "number"]},
                    "description": "按 DM 官方参数顺序传入"}}, ["method"]),

    # ================= 窗口 / 进程（目标定位） =================
    _tool("dm_find_window", "按窗口类名/标题查找窗口，返回 hwnd。本机《剑灵》约定：class='UnrealWindow' 且标题含《剑灵》。",
          {"class_name": {"type": "string", "description": "窗口类名，如 UnrealWindow"},
           "title": {"type": "string", "description": "窗口标题（支持关键字）"}}),
    _tool("dm_find_window_by_process", "按进程名查找窗口，返回 hwnd。",
          {"process_name": {"type": "string", "description": "如 bnsr.exe"},
           "title": {"type": "string"}}),
    _tool("dm_enum_window", "枚举顶层/子窗口句柄。",
          {"parent": {"type": "integer", "description": "父窗口句柄，0 表示顶层"},
           "title": {"type": "string"}, "class_name": {"type": "string"}}),
    _tool("dm_set_target", "不绑定只指定目标窗口：把 hwnd 作为后续调用的目标（适合已用其他方式绑定/只需读内存的场景）。",
          {"hwnd": HWND}, ["hwnd"]),
    _tool("dm_bind_window", "绑定窗口（BindWindowEx）。绑定后按实测约定自动 AsmSetTimeout + SetAsmHwndAsProcessId(1)。",
          {"hwnd": HWND, "display": {"type": "string", "default": "normal"},
           "mouse": {"type": "string", "default": "normal"},
           "keypad": {"type": "string", "default": "normal"},
           "public_desc": {"type": "string", "default": "normal"},
           "mode": {"type": "integer", "default": 0},
           "ex": {"type": "boolean", "description": "true 用 BindWindowEx（默认），false 用 BindWindow"}}, ["hwnd"]),
    _tool("dm_bind_hwnd",
          "★ 严格绑定**指定 hwnd**（参数传入，完全不做窗口查找、也不做类名/标题复核）。"
          "推荐流程：dm_find_window 取到 hwnd -> dm_bind_hwnd 绑定。"
          "与 dm_bind_window 的区别：本工具会把「hwnd 为空 / 未注册 / DM 返回 0」三种情况"
          "分别报成可读错误，并回显 source=explicit-hwnd，便于确认走的是严格路径。",
          {"hwnd": HWND, "display": {"type": "string", "default": "normal"},
           "mouse": {"type": "string", "default": "normal"},
           "keypad": {"type": "string", "default": "normal"},
           "public_desc": {"type": "string", "default": "normal"},
           "mode": {"type": "integer", "default": 0},
           "ex": {"type": "boolean", "description": "true 用 BindWindowEx（默认），false 用 BindWindow"}}, ["hwnd"]),
    _tool("dm_unbind_window", "解绑当前窗口。", {}),
    _tool("dm_set_asm_hwnd_as_process_id", "SetAsmHwndAsProcessId：汇编/内存通道按 hwnd 解析目标进程（实测必须置 1）。",
          {"enable": {"type": "integer", "default": 1}}),
    _tool("dm_set_memory_hwnd_as_process_id", "⚠ 不推荐置 1：本机实测置 1 后内存函数会把 hwnd 当 PID，导致读取全失败。",
          {"enable": {"type": "integer", "default": 0}}),
    _tool("dm_get_process_id", "取目标窗口的进程 ID（GetWindowProcessId）。", {"hwnd": HWND}),
    _tool("dm_get_module_base_addr", "取目标进程中指定模块基址（GetModuleBaseAddr），如 bnsr.exe -> 0x140000000。",
          {"module_name": {"type": "string", "description": "如 bnsr.exe / BNSR.exe"},
           "hwnd": HWND}, ["module_name"]),
    _tool("dm_get_window_title", "取窗口标题（GetWindowTitle）。", {"hwnd": HWND}),
    _tool("dm_get_class_name", "取窗口类名（自动兼容 GetWindowClass / GetClassName；本机 DM 7.2607 实为 GetWindowClass）。",
          {"hwnd": HWND}),
    _tool("dm_get_window_rect", "取窗口矩形（GetWindowRect），返回 [x1,y1,x2,y2]。", {"hwnd": HWND}),

    # ================= 内存读（需盾） =================
    _tool("dm_read_int", "读整数（ReadInt）。type: 0=32位 1=16位 2=8位 3=64位 4=u32 5=u16 6=u8；读 64 位指针必须 type=3。",
          {"addr": ADDR, "type": {"type": "integer", "default": 3}, "hwnd": HWND}, ["addr"]),
    _tool("dm_read_float", "读 float（ReadFloat）。", {"addr": ADDR, "hwnd": HWND}, ["addr"]),
    _tool("dm_read_double", "读 double（ReadDouble）。", {"addr": ADDR, "hwnd": HWND}, ["addr"]),
    _tool("dm_read_string", "读字符串（ReadString）。type: 0=GBK/ANSI 1=UTF-16(宽字符)。",
          {"addr": ADDR, "length": {"type": "integer", "default": 32},
           "type": {"type": "integer", "default": 0}, "hwnd": HWND}, ["addr"]),
    _tool("dm_read_data", "读原始字节（默认按 8/4/2/1 分块 ReadInt 拼接，规避原生 ReadDataAddr 对 64 位大地址不稳定）。",
          {"addr": ADDR, "length": {"type": "integer", "default": 16},
           "encoding": {"type": "string", "enum": ["hex", "base64"], "default": "hex"},
           "native": {"type": "boolean", "description": "true 走原生 ReadDataAddr（可能返回空）"},
           "hwnd": HWND}, ["addr"]),

    # ================= 内存写（需盾） =================
    _tool("dm_write_int", "写整数（WriteInt）。type 语义同 dm_read_int（0=4字节 1=2字节 2=1字节 3=8字节）。",
          {"addr": ADDR, "value": {"type": "integer"}, "type": {"type": "integer", "default": 0},
           "hwnd": HWND}, ["addr", "value"]),
    _tool("dm_write_float", "写 float（WriteFloat）。", {"addr": ADDR, "value": {"type": "number"}, "hwnd": HWND},
          ["addr", "value"]),
    _tool("dm_write_double", "写 double（WriteDouble）。", {"addr": ADDR, "value": {"type": "number"}, "hwnd": HWND},
          ["addr", "value"]),
    _tool("dm_write_string", "写字符串（WriteString）。type: 0=GBK/ANSI 1=UTF-16。",
          {"addr": ADDR, "value": {"type": "string"}, "type": {"type": "integer", "default": 0}, "hwnd": HWND},
          ["addr", "value"]),
    _tool("dm_write_data", "写原始字节（按 8/4/2/1 分块 WriteInt 落盘）。",
          {"addr": ADDR, "data": {"type": "string", "description": "hex（如 '4D 5A 90 00' 或 '4D5A9000'）或 base64"},
           "encoding": {"type": "string", "enum": ["hex", "base64"], "default": "hex"}, "hwnd": HWND},
          ["addr", "data"]),

    # ================= 内存搜索（需盾） =================
    # 参数名与 DM 真实签名对齐（来源：dm.dll 类型库）：
    #   FindInt(hwnd, addr_range, int_value_min, int_value_max, type)
    #   FindFloat/Double(hwnd, addr_range, value_min, value_max)
    #   FindString(hwnd, addr_range, string_value, type)
    #   FindData(hwnd, addr_range, data)
    # ⚠️ FindInt 本体**没有 step**：step != 1 时服务自动改用 FindIntEx。
    _tool("dm_find_int", "内存搜索整数（FindInt(hwnd,range,min,max,type)）。地址范围示例：'0x140000000-0x150000000'。"
                         "value_max 省略时按 value_min 精确匹配；step!=1 时自动改用 FindIntEx。",
          {"addr_range": {"type": "string"},
           "value_min": {"type": ["integer", "string"], "description": "数值下界（只查一个值时与 value_max 相同）"},
           "value_max": {"type": ["integer", "string"], "description": "数值上界；省略则等于 value_min"},
           "type": {"type": "integer", "description": "数据类型，同 ReadInt（默认 0=32位）", "default": 0},
           "step": {"type": "integer", "default": 1, "description": "搜索步长；!=1 时改用 FindIntEx"},
           "hwnd": HWND}, ["addr_range", "value_min"]),
    _tool("dm_find_float", "内存搜索 float（FindFloat(hwnd,range,min,max)）。",
          {"addr_range": {"type": "string"},
           "value_min": {"type": ["number", "string"]},
           "value_max": {"type": ["number", "string"], "description": "省略则等于 value_min"},
           "step": {"type": "number", "default": 1.0, "description": "!=1 时改用 FindFloatEx"},
           "hwnd": HWND}, ["addr_range", "value_min"]),
    _tool("dm_find_double", "内存搜索 double（FindDouble(hwnd,range,min,max)）。",
          {"addr_range": {"type": "string"},
           "value_min": {"type": ["number", "string"]},
           "value_max": {"type": ["number", "string"], "description": "省略则等于 value_min"},
           "step": {"type": "number", "default": 1.0, "description": "!=1 时改用 FindDoubleEx"},
           "hwnd": HWND}, ["addr_range", "value_min"]),
    _tool("dm_find_string", "内存搜索字符串（FindString(hwnd,range,value,type)）。type: 0=GBK 1=UTF-16。",
          {"addr_range": {"type": "string"}, "value": {"type": "string"},
           "type": {"type": "integer", "default": 0}, "step": {"type": "integer", "default": 1},
           "hwnd": HWND}, ["addr_range", "value"]),
    _tool("dm_find_data", "内存搜索特征字节（FindData），data 用空格分隔十六进制，支持 ?? 通配。",
          {"addr_range": {"type": "string"}, "data": {"type": "string"},
           "step": {"type": "integer", "default": 1}, "hwnd": HWND}, ["addr_range", "data"]),

    # ================= 目标进程内存操作（需盾） =================
    # 真实签名（dm.dll 类型库）：VirtualAllocEx 4 参**无 protect**；VirtualFreeEx 仅 2 参。
    _tool("dm_virtual_alloc_ex", "在目标进程申请内存（VirtualAllocEx(hwnd,addr,size,type)）。"
                                 "type: 0=32位模式 1=64位模式（剑灵等 64 位目标必须用 1）。",
          {"size": {"type": "integer"},
           "addr": {"type": "integer", "description": "期望地址，0 表示由系统决定", "default": 0},
           "type": {"type": "integer", "default": 1},
           "hwnd": HWND}, ["size"]),
    _tool("dm_virtual_protect_ex", "修改目标进程内存保护属性"
                                   "（VirtualProtectEx(hwnd,addr,size,type,old_protect)）。返回改动前的旧属性。",
          {"addr": {"type": "integer"}, "size": {"type": "integer"},
           "type": {"type": "integer", "default": 1},
           "protect": {"type": "integer", "description": "新保护属性：0x40=EXECUTE_READWRITE 0x04=READWRITE 0x20=EXECUTE_READ",
                       "default": 64},
           "hwnd": HWND}, ["addr", "size"]),
    _tool("dm_virtual_free_ex", "释放目标进程内存（VirtualFreeEx(hwnd,addr) —— 只有 2 个参数，"
                                "无 size/type；地址须为 VirtualAllocEx 返回的基址，一次释放整块）。",
          {"addr": {"type": "integer"}, "hwnd": HWND}, ["addr"]),

    # ================= 输入（辅助） =================
    _tool("dm_key_down", "按下按键（KeyDown，需已绑定窗口）。", {"vk": {"type": "integer", "description": "虚拟键码，W=0x57"}, "hwnd": HWND}, ["vk"]),
    _tool("dm_key_up", "松开按键（KeyUp）。", {"vk": {"type": "integer"}, "hwnd": HWND}, ["vk"]),
    _tool("dm_key_press", "按一下按键（KeyPress）。", {"vk": {"type": "integer"}, "hwnd": HWND}, ["vk"]),
    _tool("dm_move_to", "移动鼠标（MoveTo）。", {"x": {"type": "integer"}, "y": {"type": "integer"}}, ["x", "y"]),
    _tool("dm_left_click", "左键单击（LeftClick，需已绑定窗口）。", {}),
    _tool("dm_set_keypad_delay", "设置键盘按下/松开延时（SetKeypadDelay），字符串毫秒，如 '30'。",
          {"press_delay": {"type": "string"}, "release_delay": {"type": "string"}},
          ["press_delay", "release_delay"]),
]

TOOL_INDEX = dict((t["name"], t) for t in TOOLS)

# 需要写目标进程内存（中风险）的工具，服务会在返回中附风险标注
WRITE_TOOLS = frozenset({
    "dm_write_int", "dm_write_float", "dm_write_double", "dm_write_string",
    "dm_write_data", "dm_virtual_alloc_ex", "dm_virtual_protect_ex", "dm_virtual_free_ex",
})

# 前置条件说明（唯一事实来源是 core.py 的执行路径）：
#   真正的前置条件校验（loaded / guard / target）由 core.py 的 ``_ensure_loaded()`` /
#   ``_ensure_guard()`` / ``_target()`` 在调用链上强制。经核对，本服务 46 个工具中
#   **没有任何一个**可以在 DM 未加载时成功执行——包括 dm_status 之外的所有接口，
#   以及 dm_version / dm_set_path / dm_raw_call 这类“看起来像探针”的接口
#   （它们都要求 loaded，因为要和 DM 对象交互）。
#   因此这里不再维护一份容易与实现漂移的“免加载白名单”，只做注册表一致性自检。


def _self_check():
    """启动期一致性自检：工具名集合必须与处理器、写工具集合完全对齐。

    这类“注册表 + 分发表”结构最容易出的问题是某一侧漏了一条（表现为
    ``dm_xxx 未实现处理器`` 的运行时错误）。把它提前到模块导入时失败，
    可以在启动阶段直接暴露，而不是等某个工具被调用时才炸。
    """
    declared = set(TOOL_INDEX)
    implemented = set(_HANDLERS)
    missing = sorted(declared - implemented)
    extra = sorted(implemented - declared)
    if missing or extra:
        raise RuntimeError(
            "tools.py 工具注册表与处理器不一致："
            "缺少处理器=%s；多余处理器=%s" % (missing, extra))
    unknown_write = sorted(WRITE_TOOLS - declared)
    if unknown_write:
        raise RuntimeError("WRITE_TOOLS 中存在未声明的工具：%s" % unknown_write)


# ---------------------------------------------------------------- 分发
def call_tool(core, name, args=None):
    """执行工具。返回 ``(payload_dict, is_error)``。

    前置条件（loaded / guard / target）不在本层判断，而是在 ``core`` 的
    执行路径上由 ``_ensure_loaded`` / ``_ensure_guard`` / ``_target`` 强制；
    本层只负责：工具存在性、必填参数、结果包装与写风险标注。
    """
    args = dict(args or {})
    spec = TOOL_INDEX.get(name)
    if spec is None:
        raise E.DmMcpError(E.UNKNOWN_TOOL, "未知工具 %s" % name)
    fn = _HANDLERS.get(name)
    if fn is None:
        raise E.DmMcpError(E.INTERNAL, "工具 %s 未实现处理器" % name)
    missing = [k for k in (spec.get("inputSchema", {}).get("required") or [])
               if k not in args or args[k] is None]
    if missing:
        raise E.DmMcpError(E.INVALID_PARAM, "缺少必填参数：%s" % ", ".join(missing),
                           detail={"tool": name, "missing": missing,
                                   "required": spec.get("inputSchema", {}).get("required")})
    payload = fn(core, args)
    if isinstance(payload, dict):
        payload.setdefault("ok", True)
        if name in WRITE_TOOLS:
            payload.setdefault("risk", "中风险：已写入目标进程内存，操作不可撤销")
    else:
        payload = {"ok": True, "result": payload}
    return payload, False


# ---------------------------------------------------------------- 处理器
def _load(core, a):
    try:
        st = core.load(a.get("dll_path"), a.get("reg_code"), a.get("backend"),
                       guard=bool(a.get("guard", True)))
        return st
    except E.DmMcpError as exc:
        if exc.code == E.GUARD_NOT_LOADED:
            st = core.status()
            st["ok"] = True
            st["warning"] = "dm.dll 已加载，但 dm 盾加载失败，内存接口当前不可用"
            st["guard_error"] = exc.to_dict()
            return st
        raise


HANDLERS = {
    "dm_load": _load,
    "dm_auto_bind": lambda c, a: c.auto_bind(
        a.get("window_class", "UnrealWindow"), a.get("window_title", "剑灵"),
        a.get("module", "bnsr.exe"), (_u64(a["hwnd"]) if a.get("hwnd") else None)),
    "dm_status": lambda c, a: c.status(),
    "dm_reg": lambda c, a: {"reg_ok": c.reg(a["code"])},
    "dm_guard": lambda c, a: c.guard(bool(a.get("enable", True)), a.get("modes")),
    "dm_get_last_error": lambda c, a: {"last_error": c.get_last_error()},
    "dm_version": lambda c, a: {"version": c.raw_call("Ver")["ret"]},
    "dm_set_path": lambda c, a: {"ret": c.raw_call("SetPath", [a["path"]])["ret"]},
    "dm_raw_call": lambda c, a: c.raw_call(a["method"], a.get("args")),

    "dm_find_window": lambda c, a: c.find_window(a.get("class_name", ""), a.get("title", "")),
    "dm_find_window_by_process": lambda c, a: c.find_window_by_process(a["process_name"], a.get("title", "")),
    "dm_enum_window": lambda c, a: c.enum_window(a.get("parent", 0), a.get("title", ""), a.get("class_name", "")),
    "dm_set_target": lambda c, a: c.set_target(_u64(a["hwnd"])),
    "dm_bind_window": lambda c, a: c.bind_window(
        _u64(a["hwnd"]), a.get("display", "normal"), a.get("mouse", "normal"),
        a.get("keypad", "normal"), a.get("public_desc", "normal"), a.get("mode", 0), a.get("ex", True)),
    "dm_bind_hwnd": lambda c, a: c.bind_by_hwnd(
        a["hwnd"], a.get("display", "normal"), a.get("mouse", "normal"),
        a.get("keypad", "normal"), a.get("public_desc", "normal"), a.get("mode", 0), a.get("ex", True)),
    "dm_unbind_window": lambda c, a: c.unbind_window(),
    "dm_set_asm_hwnd_as_process_id": lambda c, a: c.set_asm_hwnd_as_process_id(a.get("enable", 1)),
    "dm_set_memory_hwnd_as_process_id": lambda c, a: c.set_memory_hwnd_as_process_id(a.get("enable", 0)),
    "dm_get_process_id": lambda c, a: c.get_process_id(a.get("hwnd")),
    "dm_get_module_base_addr": lambda c, a: c.get_module_base_addr(a["module_name"], a.get("hwnd")),
    "dm_get_window_title": lambda c, a: c.get_window_title(a.get("hwnd")),
    "dm_get_class_name": lambda c, a: c.get_class_name(a.get("hwnd")),
    "dm_get_window_rect": lambda c, a: c.get_window_rect(a.get("hwnd")),

    "dm_read_int": lambda c, a: c.read_int(_addr(a["addr"]), a.get("type", 3), a.get("hwnd")),
    "dm_read_float": lambda c, a: c.read_float(_addr(a["addr"]), a.get("hwnd")),
    "dm_read_double": lambda c, a: c.read_double(_addr(a["addr"]), a.get("hwnd")),
    "dm_read_string": lambda c, a: c.read_string(_addr(a["addr"]), a.get("length", 32),
                                                 a.get("type", 0), a.get("hwnd")),
    "dm_read_data": lambda c, a: c.read_data(_addr(a["addr"]), a.get("length", 16),
                                             a.get("encoding", "hex"), a.get("hwnd"), a.get("native", False)),
    "dm_write_int": lambda c, a: c.write_int(_addr(a["addr"]), a["value"], a.get("type", 0), a.get("hwnd")),
    "dm_write_float": lambda c, a: c.write_float(_addr(a["addr"]), a["value"], a.get("hwnd")),
    "dm_write_double": lambda c, a: c.write_double(_addr(a["addr"]), a["value"], a.get("hwnd")),
    "dm_write_string": lambda c, a: c.write_string(_addr(a["addr"]), a["value"], a.get("type", 0), a.get("hwnd")),
    "dm_write_data": lambda c, a: c.write_data(_addr(a["addr"]), a["data"], a.get("encoding", "hex"), a.get("hwnd")),

    "dm_find_int": lambda c, a: c.find_int(a["addr_range"], _int_s(a["value_min"]),
                                           None if a.get("value_max") is None else _int_s(a["value_max"]),
                                           a.get("type", 0), a.get("step", 1), a.get("hwnd")),
    "dm_find_float": lambda c, a: c.find_float(a["addr_range"], _num_s(a["value_min"]),
                                               None if a.get("value_max") is None else _num_s(a["value_max"]),
                                               a.get("step", 1.0), a.get("hwnd")),
    "dm_find_double": lambda c, a: c.find_double(a["addr_range"], _num_s(a["value_min"]),
                                                 None if a.get("value_max") is None else _num_s(a["value_max"]),
                                                 a.get("step", 1.0), a.get("hwnd")),
    "dm_find_string": lambda c, a: c.find_string(a["addr_range"], a["value"], a.get("type", 0),
                                                 a.get("step", 1), a.get("hwnd")),
    "dm_find_data": lambda c, a: c.find_data(a["addr_range"], a["data"], a.get("step", 1), a.get("hwnd")),

    "dm_virtual_alloc_ex": lambda c, a: c.virtual_alloc_ex(a["size"], a.get("addr", 0),
                                                           a.get("type", 1), a.get("hwnd")),
    "dm_virtual_protect_ex": lambda c, a: c.virtual_protect_ex(_u64(a["addr"]), a["size"],
                                                               a.get("type", 1), a.get("protect", 0x40),
                                                               a.get("hwnd")),
    "dm_virtual_free_ex": lambda c, a: c.virtual_free_ex(_u64(a["addr"]), a.get("hwnd")),

    "dm_key_down": lambda c, a: c.key_down(a["vk"], a.get("hwnd")),
    "dm_key_up": lambda c, a: c.key_up(a["vk"], a.get("hwnd")),
    "dm_key_press": lambda c, a: c.key_press(a["vk"], a.get("hwnd")),
    "dm_move_to": lambda c, a: c.move_to(a["x"], a["y"]),
    "dm_left_click": lambda c, a: c.left_click(),
    "dm_set_keypad_delay": lambda c, a: c.set_keypad_delay(a["press_delay"], a["release_delay"]),
}
_HANDLERS = HANDLERS

# 注册表与处理器的一致性自检（导入时执行一次；不一致立即抛错，不等到调用时才发现）
_self_check()
