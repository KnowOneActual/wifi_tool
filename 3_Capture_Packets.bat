@echo off
setlocal
title 802.11 RF Management Frame Capturer (TShark)
color 0E
echo =========================================================
echo      802.11 RF MANAGEMENT FRAME CAPTURE (TSHARK)
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
set /p DURATION="Enter capture duration in seconds (Default 30): "
if "%DURATION%"=="" set DURATION=30
set /p OUTNAME="Enter output filename (Default site_capture.pcapng): "
if "%OUTNAME%"=="" set OUTNAME=site_capture.pcapng
echo.
echo Starting capture on Wi-Fi interface for %DURATION% seconds...
python "%~dp0capture_packets.py" -i auto -d %DURATION% -o "%~dp0%OUTNAME%"
echo.
echo Capture complete! Saved to %OUTNAME%.
echo =========================================================
pause
