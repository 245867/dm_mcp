@echo off
rem dm-mcp: start persistent HTTP service (MCP: POST /mcp , REST: /api/<tool>)
rem NOTE: keep this file ASCII-only to avoid codepage issues on Windows.
cd /d "%~dp0"
set PYEXE=python
if exist "%~dp0python32\python.exe" set PYEXE=%~dp0python32\python.exe
rem NOTE: dm.dll is x86 (COM ProgID dm.dmsoft); a 64-bit host cannot use it.
rem       run_server.py self-checks bitness and, when this host is 64-bit,
rem       relaunches itself with a 32-bit python (auto-detected, or --python32).
echo [dm-mcp] host check : auto-relaunch as 32-bit if this host is 64-bit
echo [dm-mcp] starting HTTP service on 127.0.0.1:27043 ...
echo [dm-mcp] health : http://127.0.0.1:27043/health
echo [dm-mcp] status : http://127.0.0.1:27043/status
echo [dm-mcp] mcp    : POST http://127.0.0.1:27043/mcp
echo [dm-mcp] press Ctrl+C to stop
"%PYEXE%" run_server.py --mode http --port 27043
pause
