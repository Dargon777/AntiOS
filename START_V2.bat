@echo off
setlocal
cd /d "%~dp0"
echo === AntiOS v2 scan ===
py -3 -m antios scan
echo.
echo === AntiOS v2 doctor ===
py -3 -m antios doctor
echo.
echo AntiOS v2 made no changes. Use "py -3 -m antios apply" to preview a plan.
pause
