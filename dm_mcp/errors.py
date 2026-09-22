# -*- coding: utf-8 -*-
"""服务层错误码与异常。

约定（重要）：
    - 本模块的 code 是 **dm-mcp 服务自身** 的稳定错误码，与 DM 插件内部的 GetLastError() 无关；
    - DM 插件返回值语义：多数接口 0=失败 / 1=成功；具体失败原因由 GetLastError() 给出（0 表示无错误）。
      服务把 DM 的返回值与 last_error 一并放在 detail 中回传，不做二次解释，避免误判。
"""

OK = "OK"

# ---- 宿主/加载类 ----
NOT_32BIT = "DM_MCP_NOT_32BIT"            # 当前 Python 不是 32 位
NO_PYTHON32 = "DM_MCP_NO_PYTHON32"        # 本机未找到可用的 32 位 Python 解释器（无法自举）
RELAUNCH_FAILED = "DM_MCP_RELAUNCH_FAILED"  # 已找到 32 位解释器，但重新拉起自身失败
AUTOBIND_FAILED = "DM_MCP_AUTOBIND_FAILED"  # 启动默认绑定《剑灵》窗口失败
DLL_NOT_FOUND = "DM_DLL_NOT_FOUND"        # 找不到 dm.dll
LOAD_FAILED = "DM_LOAD_FAILED"            # dm.dll 加载 / 创建 COM 对象失败
NOT_LOADED = "DM_NOT_LOADED"              # 尚未加载 DM
EXPORT_MISSING = "DM_EXPORT_MISSING"      # dm.dll 中缺少指定导出（后端=ctypes 时）
NOT_SUPPORTED = "DM_NOT_SUPPORTED"        # 当前后端不支持该能力

# ---- 盾 / 注册 类 ----
NOT_REGISTERED = "DM_NOT_REGISTERED"      # Reg 未成功（未填注册码或注册码无效，仅警告不阻断）
GUARD_NOT_LOADED = "DM_GUARD_NOT_LOADED"  # ★ 未加载 dm 盾 -> 拒绝读写

# ---- 目标 类 ----
NO_TARGET = "DM_NO_TARGET"                # 未绑定窗口 / 未指定 hwnd

# ---- 调用 类 ----
INVALID_PARAM = "DM_INVALID_PARAM"
CALL_FAILED = "DM_CALL_FAILED"            # DM 接口调用返回失败
UNKNOWN_TOOL = "DM_UNKNOWN_TOOL"
INTERNAL = "DM_INTERNAL"

_MESSAGES = {
    OK: "成功",
    NOT_32BIT: "dm-mcp 宿主必须是 32 位 Python 进程（dm.dll 为 x86 组件）",
    NO_PYTHON32: "本机未找到可用的 32 位 Python 解释器，无法以 32 位宿主运行 dm-mcp",
    RELAUNCH_FAILED: "已找到 32 位 Python，但重新拉起自身失败",
    AUTOBIND_FAILED: "启动默认绑定《剑灵》窗口（class=UnrealWindow）失败",
    DLL_NOT_FOUND: "未找到 dm.dll，请通过 --dm-path 或 DM_DLL 环境变量或 config.json 指定",
    LOAD_FAILED: "dm.dll 加载失败（导出无法解析且 COM 组件不可用）",
    NOT_LOADED: "DM 尚未加载，请先调用 dm_load",
    EXPORT_MISSING: "dm.dll 中不存在该导出函数",
    NOT_SUPPORTED: "当前后端不支持该能力",
    NOT_REGISTERED: "DM Reg（注册）未成功；已阻止会触发进程崩溃的原生调用（DmGuard / BindWindow）",
    GUARD_NOT_LOADED: "未加载 dm 盾（DmGuard），已拒绝该内存操作。请先调用 dm_guard",
    NO_TARGET: "未绑定目标窗口，请先调用 dm_bind_window 或 dm_set_target",
    INVALID_PARAM: "参数不合法",
    CALL_FAILED: "DM 接口返回失败",
    UNKNOWN_TOOL: "未知工具名",
    INTERNAL: "服务内部错误",
}

# 公开别名：历史文档与 hostenv.py 均以 ``MESSAGES`` 引用，保留以兼容既有调用方。
MESSAGES = _MESSAGES

HINTS = {
    NOT_32BIT: "使用 32 位 Python 启动：run_server.py 会打印检测结果；或执行 自检.bat",
    NO_PYTHON32: "安装 32 位 Python（python.org 的 Windows installer (32-bit)，或 winget install --id Python.Python.3.11 --architecture x86 -e），"
                 "然后用 --python32 / config.json 的 python32_path / 环境变量 DM_MCP_PYTHON32 指定其 python.exe 绝对路径",
    RELAUNCH_FAILED: "用 --python32 显式指定 32 位 python.exe 的绝对路径后重试；也可加 --no-relaunch 只看引导信息",
    AUTOBIND_FAILED: "确认游戏已运行（class=UnrealWindow / 进程 bnsr.exe），随后手动调用 dm_auto_bind 重试",
    DLL_NOT_FOUND: "常见位置：dm.dll 同目录、注册表 HKCR\\dm.dmsoft\\CLSID 指向的路径、--dm-path 指定路径",
    LOAD_FAILED: "确认 dm.dll 位数（必须 x86）与注册状态（regsvr32 dm.dll 或 DM 自带注册工具）；用 dm_status 看后端诊断",
    NOT_LOADED: "调用 dm_load（可传 dll_path / reg_code）",
    EXPORT_MISSING: "该接口在当前后端不存在；可换后端重试（--backend com 或 dll），或用 dm_status 查看导出数",
    NOT_SUPPORTED: "换用另一后端重试（--backend dll 或 com），或先用 dm_status 确认后端能力",
    NOT_REGISTERED: "在 config.json 的 reg_code 或环境变量 DM_REG_CODE 中填入有效注册码后重启服务；未注册时 DmGuard/BindWindow 会硬崩，故被主动阻止",
    GUARD_NOT_LOADED: "调用 dm_guard（默认加载 memory2 + b3 两个盾），成功返回后即可读写",
    NO_TARGET: "先 dm_find_window / dm_find_window_by_process 拿 hwnd，再 dm_bind_window",
    INVALID_PARAM: "对照工具 inputSchema 检查参数名与类型（可调用 tools/list 取最新 schema）",
    CALL_FAILED: "用 dm_get_last_error 查看 DM 内部错误码",
    UNKNOWN_TOOL: "调用 tools/list 获取准确工具名",
    INTERNAL: "查看 dm_mcp.log 获取内部异常堆栈",
}


class DmMcpError(Exception):
    """统一的业务异常。任何工具处理器抛出本异常都会转为结构化错误结果。"""

    def __init__(self, code, message=None, hint=None, detail=None, dm_ret=None, dm_last_error=None):
        self.code = code
        self.message = message or _MESSAGES.get(code, code)
        self.hint = hint if hint is not None else HINTS.get(code, "")
        self.detail = detail
        self.dm_ret = dm_ret
        self.dm_last_error = dm_last_error
        super(DmMcpError, self).__init__("%s: %s" % (code, self.message))

    def to_dict(self):
        d = {"ok": False, "error": self.code, "message": self.message}
        if self.hint:
            d["hint"] = self.hint
        if self.detail is not None:
            d["detail"] = self.detail
        if self.dm_ret is not None:
            d["dm_return"] = self.dm_ret
        if self.dm_last_error is not None:
            d["dm_last_error"] = self.dm_last_error
        return d
