@echo off
setlocal
cd /d "%~dp0"
py -3 -m antios scan
echo.
echo AntiOS v2 defaults to read-only scan/dry-run workflows.
pause
