@echo off
setlocal
cd /d "%~dp0"
title Wi-Fi Site Survey - Local Field Console (Web UI)
color 1F

set "PYTHON_EXE="
for /f "delims=" %%p in ('where python 2^>nul') do (
    if not defined PYTHON_EXE (
        "%%p" --version >nul 2>nul
        if not errorlevel 1 set "PYTHON_EXE=%%p"
    )
)
if not defined PYTHON_EXE (
    py -3 --version >nul 2>nul
    if not errorlevel 1 (
        for /f "delims=" %%p in ('py -3 -c "import sys; print(sys.executable)" 2^>nul') do set "PYTHON_EXE=%%p"
    )
)
if not defined PYTHON_EXE (
    color 4F
    echo [!] ERROR: A working Python 3 installation was not found in your system PATH.
    echo     Install Python 3.8+ or disable the python.exe App Execution Alias in Windows Settings.
    pause
    exit /b 1
)
for %%d in ("%PYTHON_EXE%") do set "PATH=%%~dpd;%PATH%"

python "%~dp0survey_web_ui.py"
pause
