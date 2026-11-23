@echo off
setlocal DisableDelayedExpansion
chcp 65001 >nul
title MemScope demo
pushd "%~dp0" || exit /b 1

set "VENV_PY=app\.venv\Scripts\python.exe"
set "CHECK_PY=import sys; sys.exit(0 if sys.version_info >= (3, 12) else 1)"
set "CHECK_DEPS=import fastapi, uvicorn, python_multipart, xgboost, sklearn, numpy, pandas, pyarrow, httpx"

if exist "%VENV_PY%" (
    "%VENV_PY%" -c "%CHECK_PY%" >nul 2>&1
    if not errorlevel 1 goto :dependencies
)

call :find_python
if not defined PYTHON_EXE (
    echo Python 3.12 or later is required. Install it from https://www.python.org/downloads/
    goto :failure
)
echo Creating the demo environment in app\.venv ...
"%PYTHON_EXE%" %PYTHON_ARG% -m venv "app\.venv"
if errorlevel 1 goto :failure

:dependencies
"%VENV_PY%" -c "%CHECK_DEPS%" >nul 2>&1
if errorlevel 1 (
    echo Installing demo dependencies...
    "%VENV_PY%" -m pip install -r "app\requirements.txt"
    if errorlevel 1 goto :failure
)

if /i "%~1"=="--dry-run" (
    echo Demo environment is ready. Dry run complete.
    popd
    exit /b 0
)

echo Starting MemScope at http://127.0.0.1:8000
echo Press Ctrl+C to stop the server.
"%VENV_PY%" -m app.launch
set "DEMO_EXIT=%errorlevel%"
if not "%DEMO_EXIT%"=="0" if /i "%~1"=="" pause
popd
exit /b %DEMO_EXIT%

:failure
echo MemScope setup failed. Check the messages above and docs\SETUP.md.
if /i "%~1"=="" pause
popd
exit /b 1

:find_python
set "PYTHON_EXE="
set "PYTHON_ARG="
py -3.12 -c "%CHECK_PY%" >nul 2>&1
if not errorlevel 1 (
    set "PYTHON_EXE=py"
    set "PYTHON_ARG=-3.12"
    exit /b 0
)
py -3 -c "%CHECK_PY%" >nul 2>&1
if not errorlevel 1 (
    set "PYTHON_EXE=py"
    set "PYTHON_ARG=-3"
    exit /b 0
)
python -c "%CHECK_PY%" >nul 2>&1
if not errorlevel 1 set "PYTHON_EXE=python"
exit /b 0
