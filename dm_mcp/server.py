# -*- coding: utf-8 -*-
"""服务前端：MCP（stdio / HTTP JSON-RPC）+ 本地 REST 桥。

沿用本机既有约定（x64dbg-mcp-server / CE_MCP_Bridge 的分层思路）：
    宿主桥（本模块 HTTP /api/*）—— 面向脚本的简单 REST；
    MCP 适配层（/mcp 与 stdio）—— 面向 MCP 客户端的 JSON-RPC 2.0。

线程模型：COM 为 STA，故 HTTP 模式使用单线程 HTTPServer，保证所有 DM 调用落在同一线程/公寓。
stdout 在 stdio 模式下只输出 JSON-RPC 报文，日志一律写 stderr 与文件。
"""
import json
import os
import socket
import sys
import threading
import time

from . import DEFAULT_HTTP_PORT, SERVER_NAME, __version__
from . import errors as E
from . import tools as T

PROTOCOL_VERSION = "2024-11-05"
LOG_PATH = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "dm_mcp.log")

# 单次 HTTP 请求体上限（1 MiB）。本服务的工具入参是地址/数值/短字符串，
# 正常请求远小于此；设上限可避免恶意或异常的超大 body 把单线程服务拖死。
MAX_BODY_BYTES = 1 << 20

_log_lock = threading.Lock()


def log(msg):
    line = "[%s] %s" % (time.strftime("%Y-%m-%d %H:%M:%S"), msg)
    try:
        with _log_lock:
            with open(LOG_PATH, "a", encoding="utf-8") as f:
                f.write(line + "\n")
    except Exception:
        pass
    try:
        sys.stderr.write(line + "\n")
        sys.stderr.flush()
    except Exception:
        pass


# ---------------------------------------------------------------- JSON-RPC 处理
class Dispatcher(object):
    def __init__(self, core):
        self.core = core

    def handle(self, msg):
        """处理单条 JSON-RPC 消息；通知类消息返回 None。"""
        if not isinstance(msg, dict):
            return _err(None, -32600, "Invalid Request")
        mid = msg.get("id")
        method = msg.get("method")
        params = msg.get("params") or {}
        if method is None:
            return _err(mid, -32600, "Invalid Request: missing method")
        if not mid and str(method).startswith("notifications/"):
            return None  # 通知无需响应

        if method == "initialize":
            return _ok(mid, {
                "protocolVersion": PROTOCOL_VERSION,
                "capabilities": {"tools": {"listChanged": False}},
                "serverInfo": {"name": SERVER_NAME, "version": __version__},
                "instructions": "大漠插件（DM）内存读写服务。使用前：dm_load -> dm_guard -> dm_bind_window；"
                                "未加载 dm 盾时所有内存接口都会被拒绝。",
            })
        if method in ("ping",):
            return _ok(mid, {})
        if method == "tools/list":
            return _ok(mid, {"tools": T.TOOLS})
        if method == "tools/call":
            name = params.get("name")
            args = params.get("arguments") or {}
            return _ok(mid, self.call(name, args))
        if method in ("resources/list",):
            return _ok(mid, {"resources": []})
        if method in ("prompts/list",):
            return _ok(mid, {"prompts": []})
        if method in ("shutdown", "exit"):
            return _ok(mid, {})
        return _err(mid, -32601, "Method not found: %s" % method)

    def call(self, name, args):
        """执行工具，返回 MCP tool result（content + isError）。"""
        try:
            payload, is_error = T.call_tool(self.core, name, args)
        except E.DmMcpError as exc:
            log("tool %s -> error %s" % (name, exc.code))
            return {"content": [{"type": "text", "text": json.dumps(exc.to_dict(), ensure_ascii=False)}],
                    "isError": True}
        except Exception as exc:  # pragma: no cover
            err = E.DmMcpError(E.INTERNAL, "%s: %s" % (type(exc).__name__, exc))
            log("tool %s -> internal error %s" % (name, exc))
            return {"content": [{"type": "text", "text": json.dumps(err.to_dict(), ensure_ascii=False)}],
                    "isError": True}
        text = json.dumps(payload, ensure_ascii=False, default=str)
        log("tool %s -> ok" % name)
        return {"content": [{"type": "text", "text": text}], "isError": bool(is_error)}


def _ok(mid, result):
    return {"jsonrpc": "2.0", "id": mid, "result": result}


def _err(mid, code, message, data=None):
    err = {"code": code, "message": message}
    if data is not None:
        err["data"] = data
    return {"jsonrpc": "2.0", "id": mid, "error": err}


# ---------------------------------------------------------------- stdio 前端
def serve_stdio(core):
    disp = Dispatcher(core)
    log("stdio 模式启动（pid=%d，32位宿主=%s）" % (os.getpid(), core.status()["is_32bit_host"]))
    for raw in iter(sys.stdin.readline, ""):
        raw = raw.strip()
        if not raw:
            continue
        try:
            msg = json.loads(raw)
        except ValueError:
            out = _err(None, -32700, "Parse error")
            _write_stdout(out)
            continue
        if isinstance(msg, list):
            resps = [r for r in (disp.handle(m) for m in msg) if r is not None]
            if resps:
                _write_stdout(resps)
            continue
        resp = disp.handle(msg)
        if resp is not None:
            _write_stdout(resp)
    log("stdin 结束，服务退出")


def _write_stdout(obj):
    sys.stdout.write(json.dumps(obj, ensure_ascii=False))
    sys.stdout.write("\n")
    sys.stdout.flush()


# ---------------------------------------------------------------- HTTP 前端
def serve_http(core, host="127.0.0.1", port=DEFAULT_HTTP_PORT, token=None):
    from http.server import BaseHTTPRequestHandler, HTTPServer
    from urllib.parse import urlparse, parse_qs

    disp = Dispatcher(core)

    class Handler(BaseHTTPRequestHandler):
        server_version = "%s/%s" % (SERVER_NAME, __version__)
        protocol_version = "HTTP/1.1"

        # ---- 工具方法 ----
        def _send(self, obj, status=200):
            body = json.dumps(obj, ensure_ascii=False, default=str).encode("utf-8")
            self.send_response(status)
            self.send_header("Content-Type", "application/json; charset=utf-8")
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)

        def _auth_ok(self):
            if not token:
                return True
            got = self.headers.get("X-DM-Token") or parse_qs(urlparse(self.path).query).get("token", [None])[0]
            return got == token

        def _body(self):
            """读取并解析 JSON 请求体。

            超过 :data:`MAX_BODY_BYTES` 的请求直接拒绝（返回 ``_too_large`` 标记），
            避免无上限读取把单线程服务拖垮；解析失败返回 ``{"_raw": ...}`` 交由上层处理。
            """
            try:
                length = int(self.headers.get("Content-Length") or 0)
            except (TypeError, ValueError):
                length = 0
            if not length:
                return None
            if length > MAX_BODY_BYTES:
                return {"_too_large": length}
            raw = self.rfile.read(length).decode("utf-8", "replace")
            try:
                return json.loads(raw)
            except ValueError:
                return {"_raw": raw}

        def _run_tool(self, name, args):
            """执行工具并把结果作为 JSON 返回。

            HTTP 状态码语义：工具执行成功 -> 200；工具执行失败（isError）-> 200 但响应体
            里 ``ok=false``（工具级错误是本服务的正常业务结果，不应与传输层 4xx/5xx 混淆，
            否则脚本客户端的 ``urlopen`` 会抛 HTTPError 而拿不到结构化错误体）。
            仅在“未知工具”这类调用方明显用错接口的情况下返回 400。
            """
            res = disp.call(name, args or {})
            payload = res.get("content", [{}])[0].get("text", "{}")
            try:
                payload = json.loads(payload)
            except ValueError:
                pass
            status = 200
            if isinstance(payload, dict) and payload.get("error") == E.UNKNOWN_TOOL:
                status = 400
            return self._send(payload, status)

        # ---- 路由 ----
        def do_GET(self):
            u = urlparse(self.path)
            p = u.path.rstrip("/") or "/"
            if not self._auth_ok():
                return self._send({"ok": False, "error": "UNAUTHORIZED"}, 401)
            if p in ("/", "/health"):
                return self._send({"ok": True, "server": SERVER_NAME, "version": __version__,
                                   "is_32bit_host": core.status()["is_32bit_host"]})
            if p == "/status":
                return self._send(core.status())
            if p == "/tools":
                return self._send({"tools": [t["name"] for t in T.TOOLS]})
            if p.startswith("/api/"):
                name = p[len("/api/"):]
                q = parse_qs(u.query)
                args = dict((k, v[0] if len(v) == 1 else v) for k, v in q.items() if k != "token")
                return self._run_tool(name, _coerce_args(args))
            if p.startswith("/tools/"):
                return self._send(T.TOOL_INDEX.get(p[len("/tools/"):], {"error": "unknown tool"}))
            return self._send({"ok": False, "error": "NOT_FOUND", "path": p}, 404)

        def do_POST(self):
            u = urlparse(self.path)
            p = u.path.rstrip("/") or "/"
            if not self._auth_ok():
                return self._send({"ok": False, "error": "UNAUTHORIZED"}, 401)
            body = self._body() or {}
            if isinstance(body, dict) and "_too_large" in body:
                return self._send({"ok": False, "error": "REQUEST_TOO_LARGE",
                                   "message": "请求体超过 %d 字节上限" % MAX_BODY_BYTES,
                                   "length": body["_too_large"]}, 413)
            if p in ("/mcp", "/"):
                if isinstance(body, list):
                    resps = [r for r in (disp.handle(m) for m in body) if r is not None]
                    return self._send(resps)
                resp = disp.handle(body)
                return self._send(resp if resp is not None else {"jsonrpc": "2.0", "result": None})
            if p.startswith("/api/"):
                name = p[len("/api/"):]
                args = body.get("args") if isinstance(body, dict) and "args" in body else body
                return self._run_tool(name, args if isinstance(args, dict) else {})
            return self._send({"ok": False, "error": "NOT_FOUND", "path": p}, 404)

        def log_message(self, fmt, *args):  # 覆盖默认：日志进 stderr/文件
            log("http %s" % (fmt % args))

    class _Server(HTTPServer):
        """HTTPServer 的兼容子类：绕开 socket.getfqdn() 在某些解释器上的失败。

        为什么需要（实测教训，2026-09-20）：
            本机 32 位宿主是 Python **3.11.0b5**（beta 版），
            ``HTTPServer.server_bind()`` 默认会调 ``socket.getfqdn(host)`` 做反查，
            该调用在 beta/精简解释器上可能因 idna 编解码器缺失而抛
            ``LookupError: unknown encoding: idna``，**直接导致 HTTP 服务起不来**。
            这个异常发生在 ``HTTPServer.__init__`` 里，看起来像"端口占用/权限"问题，
            实际与网络无关，排查时很容易走偏。

        ``server_name`` 只用于生成 ``Host`` 头与日志，对服务功能没有任何影响，
        因此这里直接赋常量，彻底跳过反查。
        """

        allow_reuse_address = True

        def server_bind(self):
            # 跳过 HTTPServer.server_bind() 里的 getfqdn()，只做必要的 bind
            import socketserver
            socketserver.TCPServer.server_bind(self)
            host, port = self.server_address[:2]
            self.server_name = str(host)
            self.server_port = port

    httpd = _Server((host, port), Handler)
    log("HTTP 常驻模式启动：http://%s:%d  （MCP: POST /mcp ；REST: GET/POST /api/<tool>）" % (host, port))
    log("提示：DM 为 STA，HTTP 模式采用单线程串行处理以保证调用落在同一线程")
    try:
        httpd.serve_forever()
    except KeyboardInterrupt:
        log("收到中断，HTTP 服务退出")
    finally:
        httpd.server_close()


def _coerce_args(args):
    """把 URL query 的字符串参数按 schema 粗转成数字/布尔。"""
    out = {}
    for k, v in args.items():
        if isinstance(v, list):
            out[k] = v
            continue
        if isinstance(v, str):
            s = v.strip()
            low = s.lower()
            if low in ("true", "false"):
                out[k] = (low == "true")
                continue
            try:
                out[k] = int(s, 0)
                continue
            except ValueError:
                pass
            try:
                out[k] = float(s)
                continue
            except ValueError:
                pass
        out[k] = v
    return out


def port_in_use(host, port):
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    try:
        return s.connect_ex((host, port)) == 0
    finally:
        s.close()
