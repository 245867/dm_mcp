# -*- coding: utf-8 -*-
"""DM 宿主后端：把 dm.dll 的能力抽象成统一的 ``call(name, *args)``。

两条后端路径（可用 --backend auto|dll|com 指定，auto 先 COM 后 dll 直调兜底）：

    1) DllBackend —— ctypes 直接调用 dm.dll 的 C 式导出函数（如 ReadInt）。
       优点：不依赖 COM 注册；缺点：导出名可能带 stdcall 修饰（_ReadInt@12）。
       本模块自带 PE 导出表解析（list_exports），可精确匹配到真实符号名。
    2) ComBackend —— 通过 ProgID "dm.dmsoft" 创建 IDispatch，晚期绑定调用同名方法。
       优点：本机既有工程（DM_UE4_GUI / DM_UE4_32）走的正是这条路径，已被实测验证；
       缺点：要求 dm.dll 已注册为 COM 组件。

安全说明：本模块只做“加载 + 调用”，不写入任何文件；DmGuard 的加载在 core 层显式控制。
"""

import ctypes
import os
import struct

from . import errors as E

IS_64BIT_PY = ctypes.sizeof(ctypes.c_void_p) == 8

# ---------------------------------------------------------------- 返回类型表
# DM 官方接口返回值类型：多数为 long(32)；下列接口返回 64 位 / 浮点 / 字符串。
# 仅以下接口确实需要 64 位返回。
# 反例（易踩坑）：在 32 位宿主里用 c_longlong 去接一个 32 位返回值，会把 EDX 中的垃圾当高 32 位，
# 因此 hwnd/PID/BOOL 类接口一律按 32 位 long 处理。
RET_I64 = {
    "ReadInt",           # type=3 时返回 64 位
    "VirtualAllocEx",    # 64 位目标进程的分配地址可能超出 32 位
    "GetModuleBaseAddr", # 64 位模块基址可能超出 32 位（另一形式 GetModuleBaseAddrEx 返回字符串）
}
RET_F32 = {"ReadFloat"}
RET_F64 = {"ReadDouble"}
RET_STR = {
    "ReadString", "ReadData", "ReadDataAddr", "Ver", "GetPath", "GetBasePath",
    "GetWindowTitle", "GetClassName", "GetWindowClass", "EnumWindow", "EnumWindowByProcess",
    "FindWindow", "FindWindowByProcess", "FindWindowEx", "FindWindowByProcessId",
    "FindInt", "FindFloat", "FindDouble", "FindString", "FindData",
    "GetWindowProcessPath", "GetClipboard", "GetCmdStr", "GetDiskSerial", "GetMachineCode",
    "GetWindowRect", "GetClientRect",
}

# 常见 dm.dll 搜索位置（找不到时按顺序探测；顺序即优先级）
#   注意：这里**只放通用位置**，不放任何开发机上的绝对路径。
#   开发机路径既会泄露本机目录结构，写在公开仓库里对别人也毫无用处。
#   机器相关的路径请用 --dm-path / 环境变量 DM_DLL / config.json 的 dm_path 指定。
_COMMON_DLL_PATTERNS = [
    r"{root}\dm.dll",
    r"{root}\dm\dm.dll",
    r"{root}\bin\dm.dll",
    r"{root}\lib\dm.dll",
    r"{root}\sdk\dm.dll",
    r"D:\dm\dm.dll",
    r"D:\大漠\dm.dll",
    r"C:\dm\dm.dll",
]


def find_registered_dll():
    """从注册表反查已注册的 dm.dll 路径（ProgID=dm.dmsoft）。返回路径或 None。"""
    try:
        import winreg
    except ImportError:  # pragma: no cover - 非 Windows
        return None
    views = [0]
    try:
        views.append(winreg.KEY_WOW64_32KEY)
        views.append(winreg.KEY_WOW64_64KEY)
    except AttributeError:
        pass
    for view in views:
        try:
            with winreg.OpenKey(winreg.HKEY_CLASSES_ROOT, "dm.dmsoft\\CLSID", 0,
                                winreg.KEY_READ | view) as k:
                clsid = winreg.QueryValueEx(k, "")[0]
        except OSError:
            continue
        for sub in ("InprocServer32", "LocalServer32"):
            try:
                with winreg.OpenKey(winreg.HKEY_CLASSES_ROOT,
                                    "CLSID\\%s\\%s" % (clsid, sub), 0,
                                    winreg.KEY_READ | view) as k:
                    p = winreg.QueryValueEx(k, "")[0]
                    p = os.path.expandvars(p).strip('"')
                    if os.path.isfile(p):
                        return p
            except OSError:
                continue
    return None


def locate_dm_dll(explicit=None, extra_dirs=None):
    """定位 dm.dll。顺序：显式参数 -> 环境变量 -> 常见位置 -> 注册表。返回 (path, 来源说明)。"""
    cands = []
    if explicit:
        cands.append((os.path.expandvars(explicit), "参数 --dm-path"))
    for env in ("DM_DLL", "DM_PATH"):
        v = os.environ.get(env)
        if v:
            p = os.path.expandvars(v)
            if os.path.isdir(p):
                p = os.path.join(p, "dm.dll")
            cands.append((p, "环境变量 %s" % env))

    root = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
    for pat in _COMMON_DLL_PATTERNS:
        cands.append((pat.format(root=root), "常见位置"))
    for d in (extra_dirs or []):
        cands.append((os.path.join(d, "dm.dll"), "额外目录"))

    for p, src in cands:
        if p and os.path.isfile(p):
            return os.path.abspath(p), src

    reg = find_registered_dll()
    if reg:
        return os.path.abspath(reg), "注册表 dm.dmsoft"
    return None, "未找到"


# ---------------------------------------------------------------- PE 导出表
def list_exports(dll_path):
    """解析 PE 导出表，返回 (导出名集合, 错误信息)。纯标准库实现，用于诊断符号修饰。"""
    try:
        with open(dll_path, "rb") as f:
            data = f.read()
        if data[:2] != b"MZ":
            return set(), "不是 PE 文件"
        pe_off = struct.unpack_from("<I", data, 0x3C)[0]
        if data[pe_off:pe_off + 4] != b"PE\0\0":
            return set(), "PE 头无效"
        nsec = struct.unpack_from("<H", data, pe_off + 6)[0]
        opt_size = struct.unpack_from("<H", data, pe_off + 20)[0]
        opt_off = pe_off + 24
        magic = struct.unpack_from("<H", data, opt_off)[0]
        dd_off = opt_off + (96 if magic == 0x10B else 112)
        exp_rva, exp_size = struct.unpack_from("<II", data, dd_off)
        if not exp_rva:
            return set(), "无导出目录"
        sec_off = opt_off + opt_size
        sections = []
        for i in range(nsec):
            s = sec_off + i * 40
            name = data[s:s + 8].rstrip(b"\0").decode("latin-1", "ignore")
            vsz, va, rsz, ra = struct.unpack_from("<IIII", data, s + 8)
            sections.append((name, va, max(vsz, rsz), ra))

        def rva2off(rva):
            for _n, va, vsz, ra in sections:
                if va <= rva < va + vsz:
                    return ra + (rva - va)
            return None

        off = rva2off(exp_rva)
        if off is None:
            return set(), "导出目录不在节内"
        nfunc, nname = struct.unpack_from("<II", data, off + 20)
        name_rva = struct.unpack_from("<I", data, off + 32)[0]
        noff = rva2off(name_rva)
        names = set()
        for i in range(nname):
            nr = struct.unpack_from("<I", data, noff + i * 4)[0]
            o = rva2off(nr)
            if o is None:
                continue
            end = data.find(b"\0", o)
            names.add(data[o:end].decode("latin-1", "ignore"))
        return names, None
    except Exception as exc:  # pragma: no cover
        return set(), "解析失败: %s" % exc


# ---------------------------------------------------------------- DLL 后端
class DllBackend(object):
    name = "dll"

    def __init__(self, dll_path, exports=None):
        self.dll_path = dll_path
        self._dll = None
        self._exports = exports or set()
        self._free = None

    def load(self):
        last = None
        for loader in (ctypes.WinDLL, ctypes.CDLL):
            try:
                self._dll = loader(self.dll_path)
                break
            except OSError as exc:
                last = exc
        if self._dll is None:
            raise E.DmMcpError(E.LOAD_FAILED, "LoadLibrary 失败", detail=str(last or ""))
        if not self._exports:
            self._exports, _err = list_exports(self.dll_path)
        return True

    def _resolve(self, name, argc):
        """解析真实导出符号：ReadInt / _ReadInt@12 / ReadInt@12 等。"""
        dll = self._dll
        cands = [name]
        if not IS_64BIT_PY:
            nbytes = 4 * argc
            cands += ["_%s@%d" % (name, nbytes), "%s@%d" % (name, nbytes)]
        # 若已知导出集合，优先使用集合中真实存在的名字
        for c in list(cands):
            if self._exports and c in self._exports:
                cands.insert(0, c)
                break
        for c in cands:
            fn = getattr(dll, c, None)
            if fn is not None:
                return fn, c
        return None, None
    def call(self, name, *args):
        if self._dll is None:
            raise E.DmMcpError(E.NOT_LOADED, "DLL 后端尚未加载")
        fn, real = self._resolve(name, len(args))
        if fn is None:
            raise E.DmMcpError(
                E.EXPORT_MISSING, "dm.dll 中未找到导出 %s" % name,
                detail={"exports_sample": sorted(list(self._exports))[:40]})
        # 参数类型（关键）：32 位宿主下 DM 的整型参数均为 32 位，必须按 32 位入栈；
        # 若用 c_longlong 传 8 字节，stdcall 清栈字节数不匹配会破坏调用方栈（直调 dll 最易踩的坑）。
        n = len(args)
        cargs, atypes = [], []
        for i, a in enumerate(args):
            if isinstance(a, str):
                cargs.append(ctypes.c_char_p(a.encode("mbcs", "replace")))
                atypes.append(ctypes.c_char_p)
            elif isinstance(a, bool):
                cargs.append(ctypes.c_int(1 if a else 0))
                atypes.append(ctypes.c_int)
            elif isinstance(a, float):
                # DM 中仅 WriteFloat 的 value 与 FindFloat 的 value/step 是 32 位 float，其余为 double
                use_f32 = (name == "WriteFloat" and i == n - 1) or (name == "FindFloat" and i >= n - 2)
                cargs.append(ctypes.c_float(a) if use_f32 else ctypes.c_double(a))
                atypes.append(ctypes.c_float if use_f32 else ctypes.c_double)
            else:
                iv = int(a)
                cargs.append(ctypes.c_int(iv) if iv < 0 else ctypes.c_uint(iv))
                atypes.append(ctypes.c_int if iv < 0 else ctypes.c_uint)
        fn.argtypes = atypes
        if name in RET_STR:
            fn.restype = ctypes.c_char_p
        elif name in RET_I64:
            fn.restype = ctypes.c_longlong
        elif name in RET_F32:
            fn.restype = ctypes.c_float
        elif name in RET_F64:
            fn.restype = ctypes.c_double
        else:
            fn.restype = ctypes.c_long
        ret = fn(*cargs)
        if name in RET_STR:
            if ret is None:
                return ""
            return ret.decode("mbcs", "replace")
        if isinstance(ret, float):
            return ret
        return int(ret)

    def describe(self):
        return {"backend": self.name, "dll_path": self.dll_path,
                "exports_found": len(self._exports)}


# ---------------------------------------------------------------- COM 后端
_CLSCTX_INPROC_SERVER = 1
_DISPATCH_METHOD = 1
_DISPATCH_PROPERTYGET = 2
_VT_EMPTY, _VT_NULL, _VT_I2, _VT_I4, _VT_R4, _VT_R8, _VT_BSTR, _VT_I8 = 0, 1, 2, 3, 4, 5, 8, 20
_VT_BYREF = 0x4000


class _GUID(ctypes.Structure):
    _fields_ = [("Data1", ctypes.c_ulong), ("Data2", ctypes.c_ushort),
                ("Data3", ctypes.c_ushort), ("Data4", ctypes.c_ubyte * 8)]


class _VUNION(ctypes.Union):
    _fields_ = [("llVal", ctypes.c_longlong), ("lVal", ctypes.c_long),
                ("dblVal", ctypes.c_double), ("fltVal", ctypes.c_float),
                ("bstrVal", ctypes.c_void_p), ("punkVal", ctypes.c_void_p),
                ("pdispVal", ctypes.c_void_p), ("uiVal", ctypes.c_ulong),
                ("boolVal", ctypes.c_short), ("cVal", ctypes.c_char)]


class _VARIANT(ctypes.Structure):
    _fields_ = [("vt", ctypes.c_ushort), ("r1", ctypes.c_ushort),
                ("r2", ctypes.c_ushort), ("r3", ctypes.c_ushort), ("v", _VUNION)]


class _DISPPARAMS(ctypes.Structure):
    _fields_ = [("rgvarg", ctypes.POINTER(_VARIANT)),
                ("rgdispidNamedArgs", ctypes.POINTER(ctypes.c_long)),
                ("cArgs", ctypes.c_uint), ("cNamedArgs", ctypes.c_uint)]


class _EXCEPINFO(ctypes.Structure):
    _fields_ = [("wCode", ctypes.c_ushort), ("wReserved", ctypes.c_ushort),
                ("bstrSource", ctypes.c_void_p), ("bstrDescription", ctypes.c_void_p),
                ("bstrHelpFile", ctypes.c_void_p), ("dwHelpContext", ctypes.c_ulong),
                ("pvReserved", ctypes.c_void_p), ("pfnDeferredFillIn", ctypes.c_void_p),
                ("scode", ctypes.c_long)]


_HRESULT = ctypes.c_long


class ComBackend(object):
    """通过 ProgID dm.dmsoft 晚期绑定调用。仅 32 位进程可用。"""

    name = "com"

    def __init__(self, prog_id="dm.dmsoft"):
        self.prog_id = prog_id
        self._pdisp = None
        self._ole32 = None
        self._oleaut32 = None
        self._iid_idispatch = None
        self._coinit = False

    def load(self):
        if IS_64BIT_PY:
            raise E.DmMcpError(E.NOT_32BIT, "64 位进程无法创建 32 位 dm.dmsoft COM 对象",
                               hint="请使用 32 位 Python 运行")
        self._ole32 = ctypes.OleDLL("ole32")
        self._oleaut32 = ctypes.OleDLL("oleaut32")
        try:
            hr = self._ole32.CoInitializeEx(None, 2)  # COINIT_APARTMENTTHREADED
            self._coinit = hr in (0, 1)
        except Exception:
            pass
        clsid = _GUID()
        hr = self._ole32.CLSIDFromProgID(ctypes.c_wchar_p(self.prog_id), ctypes.byref(clsid))
        if hr < 0:
            raise E.DmMcpError(E.LOAD_FAILED, "CLSIDFromProgID(%s) 失败" % self.prog_id,
                               detail={"hresult": hr})
        self._iid_idispatch = _GUID(0x00020400, 0, 0, (ctypes.c_ubyte * 8)(0xC0, 0, 0, 0, 0, 0, 0, 0x46))
        pdisp = ctypes.c_void_p()
        hr = self._ole32.CoCreateInstance(ctypes.byref(clsid), None, _CLSCTX_INPROC_SERVER,
                                          ctypes.byref(self._iid_idispatch), ctypes.byref(pdisp))
        if hr < 0 or not pdisp:
            raise E.DmMcpError(E.LOAD_FAILED, "CoCreateInstance(dm.dmsoft) 失败",
                               detail={"hresult": hr,
                                       "hint": "确认 dm.dll 已注册（同目录 dm.dll + 注册工具/regsvr32）"})
        self._pdisp = pdisp
        return True

    # -- IDispatch 调用 ---------------------------------------------------
    def _vtbl(self):
        p = ctypes.cast(self._pdisp, ctypes.POINTER(ctypes.c_void_p))[0]
        return ctypes.cast(p, ctypes.POINTER(ctypes.c_void_p))

    def _get_dispid(self, name):
        ids = ctypes.c_long(0)
        names = (ctypes.c_wchar_p * 1)(name)
        fn = ctypes.WINFUNCTYPE(_HRESULT, ctypes.c_void_p, ctypes.POINTER(_GUID),
                                ctypes.POINTER(ctypes.c_wchar_p), ctypes.c_uint,
                                ctypes.c_ulong, ctypes.POINTER(ctypes.c_long))(self._vtbl()[5])
        hr = fn(self._pdisp, ctypes.byref(self._iid_idispatch), names, 1, 0, ctypes.byref(ids))
        if hr < 0:
            return None
        return ids.value

    def _make_variant(self, value):
        v = _VARIANT()
        if isinstance(value, bool):
            v.vt, v.v.lVal = _VT_I4, int(value)
        elif isinstance(value, float):
            v.vt, v.v.dblVal = _VT_R8, value
        elif isinstance(value, str):
            v.vt = _VT_BSTR
            v.v.bstrVal = self._oleaut32.SysAllocString(ctypes.c_wchar_p(value))
        else:
            iv = int(value)
            if -2147483648 <= iv <= 2147483647:
                v.vt, v.v.lVal = _VT_I4, iv
            else:
                v.vt, v.v.llVal = _VT_I8, iv
        return v

    def call(self, name, *args):
        if self._pdisp is None:
            raise E.DmMcpError(E.NOT_LOADED, "COM 后端尚未加载")
        dispid = self._get_dispid(name)
        if dispid is None:
            # COM 后端走 IDispatch 晚期绑定：接口名不存在时拿不到 dispid。
            # 这既可能是“该 dm.dll 版本确实没有这个接口”，也可能是“只以 C 式导出提供”，
            # 因此给出 NOT_SUPPORTED 并提示可回退到 dll 后端（比笼统的 EXPORT_MISSING 更好定位）。
            raise E.DmMcpError(
                E.NOT_SUPPORTED, "COM 对象（ProgID=%s）不支持方法 %s" % (self.prog_id, name),
                hint="该接口可能只以 C 式导出提供；可改用 --backend dll 或 auto 重试")
        n = len(args)
        arr = (_VARIANT * max(n, 1))()
        for i, a in enumerate(args):  # COM 参数逆序
            arr[n - 1 - i] = self._make_variant(a)
        dp = _DISPPARAMS(ctypes.cast(arr, ctypes.POINTER(_VARIANT)), None, n, 0)
        res = _VARIANT()
        ei = _EXCEPINFO()
        err = ctypes.c_uint(0)
        fn = ctypes.WINFUNCTYPE(_HRESULT, ctypes.c_void_p, ctypes.c_long, ctypes.POINTER(_GUID),
                                ctypes.c_ulong, ctypes.c_ushort, ctypes.POINTER(_DISPPARAMS),
                                ctypes.POINTER(_VARIANT), ctypes.POINTER(_EXCEPINFO),
                                ctypes.POINTER(ctypes.c_uint))(self._vtbl()[6])
        hr = fn(self._pdisp, dispid, ctypes.byref(self._iid_idispatch), 0,
                _DISPATCH_METHOD | _DISPATCH_PROPERTYGET, ctypes.byref(dp),
                ctypes.byref(res), ctypes.byref(ei), ctypes.byref(err))
        # 释放 BSTR 入参
        for i in range(n):
            v = arr[i]
            if v.vt == _VT_BSTR and v.v.bstrVal:
                self._oleaut32.SysFreeString(ctypes.c_void_p(v.v.bstrVal))
        if hr < 0:
            desc = ""
            if ei.bstrDescription:
                desc = ctypes.c_wchar_p(ei.bstrDescription).value or ""
            raise E.DmMcpError(E.CALL_FAILED, "IDispatch::Invoke(%s) 失败" % name,
                               detail={"hresult": hr, "excep": desc})
        out = None
        if res.vt == _VT_BSTR and res.v.bstrVal:
            out = ctypes.c_wchar_p(res.v.bstrVal).value
            self._oleaut32.SysFreeString(ctypes.c_void_p(res.v.bstrVal))
        elif res.vt == _VT_R8:
            out = float(res.v.dblVal)
        elif res.vt == _VT_R4:
            out = float(res.v.fltVal)
        elif res.vt in (_VT_I4, _VT_I2):
            out = int(res.v.lVal)
        elif res.vt == _VT_I8:
            out = int(res.v.llVal)
        elif res.vt in (_VT_EMPTY, _VT_NULL):
            out = 0
        else:
            out = int(res.v.llVal) if res.v.llVal is not None else 0
        if name in RET_STR and out is None:
            out = ""
        return out

    def describe(self):
        return {"backend": self.name, "prog_id": self.prog_id}


def create_backend(dll_path=None, backend="auto", prog_id="dm.dmsoft"):
    """按 auto|dll|com 创建后端，返回 (backend 实例, 诊断信息列表)。"""
    notes = []
    if backend == "dll":
        path, src = locate_dm_dll(dll_path)
        if not path:
            raise E.DmMcpError(E.DLL_NOT_FOUND, detail={"searched_from": src})
        b = DllBackend(path)
        b.load()
        notes.append("dll 后端加载成功（%s，来源：%s）" % (path, src))
        return b, notes
    if backend == "com":
        b = ComBackend(prog_id)
        b.load()
        notes.append("COM 后端加载成功（ProgID=%s）" % prog_id)
        return b, notes

    # auto：先 COM（既有工程实测路径，返回值走 VARIANT、语义完整），再 dll 直调（免注册调用兜底）
    try:
        b = ComBackend(prog_id)
        b.load()
        notes.append("COM 后端加载成功（ProgID=%s）" % prog_id)
        return b, notes
    except E.DmMcpError as exc:
        notes.append("COM 后端不可用：%s（%s）" % (exc.message, exc.detail))
    path, src = locate_dm_dll(dll_path)
    if path:
        try:
            b = DllBackend(path)
            b.load()
            exports, err = list_exports(path)
            if exports and not any(e in exports for e in ("ReadInt", "_ReadInt@12", "_ReadInt@16")):
                notes.append("已加载 %s，但未在导出表中发现 ReadInt（导出数=%d%s）"
                             % (path, len(exports), ("，%s" % err) if err else ""))
            else:
                notes.append("dll 后端加载成功（%s，来源：%s，导出数=%d；直调为兜底路径，"
                             "地址/返回值有歧义时请以返回的 raw 字段核对）" % (path, src, len(exports)))
                return b, notes
        except E.DmMcpError as exc:
            notes.append("dll 后端不可用：%s" % exc.message)
    else:
        notes.append("未定位到 dm.dll（%s）" % src)
    raise E.DmMcpError(E.LOAD_FAILED, "COM 与 dll 两条后端均不可用", detail={"notes": notes})
