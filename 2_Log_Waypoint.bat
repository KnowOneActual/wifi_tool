@echo off
setlocal
title Wi-Fi Waypoint Survey Logger
color 0B
echo =========================================================
echo         WI-FI SITE SURVEY WAYPOINT LOGGER
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
set /p WAYPOINT="Enter Room / Waypoint Name (e.g. Living Room, Office 101): "
if "%WAYPOINT%"=="" (
    echo [!] No waypoint entered. Exiting.
    pause
    exit /b
)
set /p SSID="Enter Target SSID to filter (Press Enter to log all networks): "
echo.
echo Scanning and recording at '%WAYPOINT%'...
if "%SSID%"=="" (
    python "%~dp0survey_scanner.py" --waypoint "%WAYPOINT%" --out "%~dp0survey_log.csv"
) else (
    python "%~dp0survey_scanner.py" --waypoint "%WAYPOINT%" --ssid "%SSID%" --out "%~dp0survey_log.csv"
)
echo.
echo Data saved to "%~dp0survey_log.csv".
echo =========================================================
pause
