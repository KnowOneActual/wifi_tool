@echo off
setlocal
title Wi-Fi Live Scanner (2.4 / 5 / 6 GHz)
color 0A
echo =========================================================
echo         OPEN-SOURCE WI-FI LIVE SCANNER (WIN 11)
echo =========================================================
echo.
set "PYTHON_EXE="
for /f "delims=" %%p in ('where python 2^>nul') do if not defined PYTHON_EXE ("%%p" --version >nul 2>nul && set "PYTHON_EXE=%%p")
if not defined PYTHON_EXE (
    py -3 --version >nul 2>nul
    if not errorlevel 1 (
        for /f "delims=" %%p in ('py -3 -c "import sys; print(sys.executable)" 2^>nul') do set "PYTHON_EXE=%%p"
    )
)
if not defined PYTHON_EXE (
    echo [!] ERROR: Working Python 3 not found in PATH.
    echo     Install Python 3.8+ or disable the python.exe App Execution Alias in Windows Settings.
    pause
    exit /b 1
)
for %%d in ("%PYTHON_EXE%") do set "PATH=%%~dpd;%PATH%"
python "%~dp0survey_scanner.py" --scan
echo.
echo =========================================================
pause
