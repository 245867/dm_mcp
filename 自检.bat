@echo off
rem dm-mcp self test: load dm.dll -> reg -> DmGuard -> bind window -> real memory read
rem NOTE: keep this file ASCII-only to avoid codepage issues on Windows.
cd /d "%~dp0"
set PYEXE=python
if exist "%~dp0python32\python.exe" set PYEXE=%~dp0python32\python.exe
echo [dm-mcp] checking host bitness ...
"%PYEXE%" -c "import ctypes;print('pointer size =',ctypes.sizeof(ctypes.c_void_p)*8,'bit')"
echo [dm-mcp] NOTE: pointer size must be 32. If it is 64, run_server.py will
echo [dm-mcp]       auto-relaunch itself with a 32-bit python (or print a guide).
echo.
echo [dm-mcp] running self test (read-only) ...
"%PYEXE%" run_server.py --check
echo.
echo [dm-mcp] to verify WRITE ability as well, run:
echo     "%PYEXE%" run_server.py --check --allow-write
pause
