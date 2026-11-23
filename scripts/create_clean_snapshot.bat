@echo off
setlocal DisableDelayedExpansion
chcp 65001 >nul
echo Creating the clean snapshot of the installed Windows lab guest...
powershell.exe -NoProfile -ExecutionPolicy Bypass -File "%~dp0prepare_windows_vm.ps1" -SnapshotOnly
exit /b %errorlevel%
