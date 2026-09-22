# -*- coding: utf-8 -*-
"""dm-mcp：大漠插件（DM, dm.dll）MCP 服务。

架构（沿用本机既有约定：宿主桥 + MCP 适配层）：
    dm_mcp.backend  DM 宿主后端（ctypes 直调 dm.dll 导出 / COM IDispatch 晚期绑定）
    dm_mcp.core     DM 能力核心（生命周期、盾、绑定、内存读写、搜索、内存操作）
    dm_mcp.tools    工具注册表（MCP tools/list / tools/call 的唯一事实来源）
    dm_mcp.server   MCP stdio 适配层 + 本地 REST 桥（127.0.0.1:27043）

硬约束：
    1) 宿主进程必须是 32 位（dm.dll 为 x86 组件，且 DM 通过内核级 DmGuard 访问 64 位目标进程）；
    2) 必须先 Reg -> DmGuard(1, "memory2"/"b3") 加载 dm 盾，未加载盾时所有内存读写/搜索/内存操作接口直接拒绝。
"""

__version__ = "1.1.2"
SERVER_NAME = "dm-mcp"
DEFAULT_HTTP_PORT = 27043

__all__ = ["__version__", "SERVER_NAME", "DEFAULT_HTTP_PORT"]
