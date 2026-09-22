# -*- coding: utf-8 -*-
"""验证 addr_str / addr_str_range 修复（离线，不需要注册码/游戏）。

背景（实测教训，2026-09-20）：
    DM 的地址类接口只认**十六进制字符串**。传十进制字符串（str(addr)）时
    DM 不报错、GetLastError 也是 0，但**静默返回 0** —— 属最危险的一类 bug。
    本脚本用"假后端"断言 core 层交给 DM 的地址参数一定是 hex 字符串，
    保证这类回归不会再溜进线上。

运行：
    python tests_addr_format.py
"""
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from dm_mcp.core import DmCore, addr_str, addr_str_range   # noqa: E402

PASS, FAIL = [], []


def check(name, cond, detail=""):
    (PASS if cond else FAIL).append(name)
    print("  %s %s%s" % ("[OK]" if cond else "[!!]", name, ("  " + detail) if detail else ""))


class RecordingBackend(object):
    """假后端：记录每次 call 的参数，并按需返回可控结果。"""

    def __init__(self):
        self.calls = []
        self.responses = {}

    def describe(self):
        return "recording-backend"

    def call(self, name, *args):
        self.calls.append((name, args))
        if name in self.responses:
            return self.responses[name]
        if name == "Ver":
            return "7.2607"
        if name == "GetLastError":
            return 0
        if name == "Reg":
            return 1
        if name == "GetWindowClass":
            return "UnrealWindow"
        if name == "ReadInt":
            # 模拟真实 DM：只有 hex 地址才给真数据，十进制一律 0
            addr = str(args[1]) if len(args) > 1 else ""
            return 12894362189 if addr.lower().startswith("0x") else 0
        return 1

    def last_args(self, name):
        for n, a in reversed(self.calls):
            if n == name:
                return a
        return None


def make_core():
    """构造一个"假装已加载且盾已就绪"的 core，使读写接口可直接被调用。"""
    be = RecordingBackend()
    c = DmCore(reg_code="dummy", extra_code="TEST_EXTRA", window_class="UnrealWindow")
    c._be = be
    c._notes = []
    c._version = "7.2607"
    c._reg_ok = True          # 绕过 _ensure_reg_for_native
    c._guard_loaded = True    # 绕过 _ensure_guard
    c._hwnd = 1114802
    return c, be


def test_addr_str():
    print("\n[1] addr_str() 归一化")
    check("int -> 0x hex", addr_str(0x140000000) == "0x140000000")
    check("十进制 int 也转 hex", addr_str(5368709120) == "0x140000000")
    check("hex 字符串保持", addr_str("0x140000000") == "0x140000000")
    check("十进制字符串转 hex", addr_str("5368709120") == "0x140000000")
    check("0 合法", addr_str(0) == "0x0")
    check("None 安全降级", addr_str(None) == "0x0")
    check("垃圾输入不抛异常", addr_str("not-an-addr") == "0x0")


def test_addr_str_range():
    print("\n[2] addr_str_range() 归一化")
    check("hex-hex 保持", addr_str_range("0x140000000-0x150000000") == "0x140000000-0x150000000")
    check("十进制范围转 hex",
          addr_str_range("5368709120-5637144576") == "0x140000000-0x150000000")
    check("冒号分隔符兼容", addr_str_range("0x140000000:0x150000000") == "0x140000000-0x150000000")
    check("波浪号分隔符兼容", addr_str_range("0x140000000~0x150000000") == "0x140000000-0x150000000")
    check("单地址补成范围", addr_str_range("0x140000000") == "0x140000000-0x140000000")
    check("空串原样返回", addr_str_range("") == "")
    check("None 原样返回", addr_str_range(None) is None)


def test_read_paths():
    print("\n[3] 读接口交给 DM 的地址必须是 hex")
    c, be = make_core()
    c.read_int(0x140000000, 3)
    args = be.last_args("ReadInt")
    check("read_int 传 hex", args[1] == "0x140000000", "实际 %r" % (args[1],))
    check("read_int 不再传十进制", args[1] != "5368709120")
    check("read_int 返回真实值（MZ 头低 32 位）",
          c.read_int(0x140000000, 3)["value"] == 12894362189)

    c.read_string(0x140000000, 32, 0)
    args = be.last_args("ReadString")
    check("read_string 传 hex", args[1] == "0x140000000", "实际 %r" % (args[1],))

    c.read_float(0x140000000)
    args = be.last_args("ReadFloat")
    check("read_float 传 hex", args[1] == "0x140000000", "实际 %r" % (args[1],))

    c.read_double(0x140000000)
    args = be.last_args("ReadDouble")
    check("read_double 传 hex", args[1] == "0x140000000", "实际 %r" % (args[1],))


def test_chunked_io():
    print("\n[4] 分块读写的每个地址都必须是 hex")
    c, be = make_core()
    be.responses["ReadInt"] = 0x4D5A9000
    c.read_raw_bytes(0x140000000, 10)
    int_calls = [a for n, a in be.calls if n == "ReadInt"]
    # 10 字节按 8/4/2/1 贪心分块 -> 8 字节(1 次 type=3) + 2 字节(1 次 type=1) = 2 次
    check("read_raw_bytes 发起 2 次（8+2）", len(int_calls) == 2, "实际 %d 次" % len(int_calls))
    check("read_raw_bytes 首地址 hex", bool(int_calls) and int_calls[0][1] == "0x140000000")
    check("read_raw_bytes 偏移地址也 hex",
          bool(int_calls) and int_calls[-1][1] == "0x140000008",
          "实际 %r" % (int_calls[-1][1] if int_calls else None,))
    check("read_raw_bytes 无十进制地址",
          bool(int_calls) and all(str(a[1]).startswith("0x") for a in int_calls))

    be.calls = []
    c.write_raw_bytes(0x140000000, b"\x01\x02\x03\x04\x05")
    w_calls = [a for n, a in be.calls if n == "WriteInt"]
    check("write_raw_bytes 无十进制地址",
          w_calls and all(str(a[1]).startswith("0x") for a in w_calls),
          "实际 %s" % ([a[1] for a in w_calls],))
    check("write_raw_bytes 首地址 hex", w_calls and w_calls[0][1] == "0x140000000")


def test_write_paths():
    print("\n[5] 写接口与返回值")
    c, be = make_core()
    r = c.write_int(0x140000000, 123, 0)
    args = be.last_args("WriteInt")
    check("write_int 传 hex", args[1] == "0x140000000", "实际 %r" % (args[1],))
    check("write_int 回显 addr 为 hex", r["addr"] == "0x140000000", "实际 %r" % r["addr"])

    r = c.write_float(0x140000000, 1.5)
    check("write_float 回显 addr 为 hex", r["addr"] == "0x140000000")

    r = c.write_double(0x140000000, 1.5)
    check("write_double 回显 addr 为 hex", r["addr"] == "0x140000000")

    r = c.write_string(0x140000000, "abc", 0)
    check("write_string 回显 addr 为 hex", r["addr"] == "0x140000000")


def test_find_paths():
    print("\n[6] 搜索接口的地址范围必须是 hex")
    c, be = make_core()
    be.responses["FindInt"] = "0x140000010,0x140000020"
    r = c.find_int("5368709120-5637144576", 123, 0, 1)
    args = be.last_args("FindInt")
    check("find_int 范围转 hex", args[1] == "0x140000000-0x150000000", "实际 %r" % (args[1],))
    check("find_int 解析出地址", r["addresses"] == ["0x140000010", "0x140000020"])

    print("\n[6b] Find* 的数值参数必须是十进制字符串（BSTR），不能带 0x 前缀")
    # DM 类型库里 FindInt 的 min/max/type 声明为 BSTR，传 int 会 DISP_E_TYPEMISMATCH；
    # 而搜索"数值"时如果被误转成 "0x..." 十六进制字面量，DM 会解析错，搜不到目标。
    c, be = make_core()
    be.responses["FindInt"] = "0x140000010"
    c.find_int("0x140000000-0x150000000", 23117, 23117, 0)
    args = be.last_args("FindInt")
    check("FindInt value_min 是十进制字符串", args[2] == "23117", "实际 %r" % (args[2],))
    check("FindInt value_max 是十进制字符串", args[3] == "23117", "实际 %r" % (args[3],))
    check("FindInt value_min 不带 0x 前缀", not str(args[2]).lower().startswith("0x"))
    check("FindInt type 是字符串", args[4] == "0", "实际 %r" % (args[4],))

    # 大整数（int64）不能丢精度，必须走十进制字符串而不是 float 路径
    c, be = make_core()
    be.responses["FindIntEx"] = "0x140000010"
    c.find_int("0x140000000-0x150000000", 0x1122334455667788, 0x1122334455667788, type=3, step=4)
    args = be.last_args("FindIntEx")
    check("FindIntEx 大整数保持精度", args[2] == str(0x1122334455667788), "实际 %r" % (args[2],))
    check("FindIntEx 大整数是十进制", args[2] == "1234605616436508552", "实际 %r" % (args[2],))


def test_extra_code():
    print("\n[7] 附加码（Reg 第 2 参数）")
    # 这里用**显然的假值**：真实注册码/附加码绝不出现在仓库里（含测试夹具），
    # 本测试只关心"Reg 的第二个参数是不是附加码"这个传参行为。
    c, be = make_core()
    c.reg("TEST_REG_CODE")
    args = be.last_args("Reg")
    check("Reg 传 2 个参数", len(args) == 2, "实际 %d 个" % len(args))
    check("Reg 第 2 参 = 附加码", args[1] == "TEST_EXTRA", "实际 %r" % (args[1],))

    c2, be2 = make_core()
    c2.reg("TEST_REG_CODE", "OTHER")
    check("reg() 显式附加码可覆盖", be2.last_args("Reg")[1] == "OTHER")

    c3 = DmCore(reg_code="x")
    check("未配置附加码时为空串而非 None", c3.extra_code == "")

    print("\n[8] status() 不回显凭据明文")
    c4, _ = make_core()
    s = c4.status()
    check("reg_code_configured 为布尔", isinstance(s.get("reg_code_configured"), bool))
    check("extra_code_configured 为布尔", isinstance(s.get("extra_code_configured"), bool))
    blob = repr(s)
    check("status 不含注册码明文", "TEST_REG_CODE" not in blob and "dummy" not in blob)
    check("status 不含附加码明文", "TEST_EXTRA" not in blob)


if __name__ == "__main__":
    print("=" * 64)
    print("addr_str / addr_str_range / extra_code 回归测试（离线）")
    print("=" * 64)
    test_addr_str()
    test_addr_str_range()
    test_read_paths()
    test_chunked_io()
    test_write_paths()
    test_find_paths()
    test_extra_code()
    print("\n" + "=" * 64)
    print("通过 %d 项，失败 %d 项" % (len(PASS), len(FAIL)))
    if FAIL:
        for f in FAIL:
            print("  失败：%s" % f)
    print("=" * 64)
    sys.exit(1 if FAIL else 0)
