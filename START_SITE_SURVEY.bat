@echo off
setlocal EnableDelayedExpansion
cd /d "%~dp0"
title Field Site Survey - Technician Workflow Assistant v2.0-beta
color 1F

:: Ensure Jobs root directory exists
if not exist "%~dp0Jobs" mkdir "%~dp0Jobs"

cls
echo ===============================================================================
echo          WI-FI SITE SURVEY - FIELD TECHNICIAN ASSISTANT (v2.0-BETA)
echo ===============================================================================
echo  [!] BETA TESTING NOTICE: Do not use as sole production deliverable yet.
echo      All feedback and bug reports are welcome:
echo      https://github.com/KnowOneActual/wifi_tool/issues
echo ===============================================================================
echo.

:: Pre-Flight Check: Verify Python is installed and accessible
where python >nul 2>nul
if errorlevel 1 (
    color 4F
    echo [!] ERROR: Python 3 was not found in your system PATH.
    echo     Please install Python 3.8+ from https://www.python.org/downloads/
    echo     ^(Make sure to check "Add python.exe to PATH" during installation^).
    echo.
    pause
    exit /b 1
)

:: Auto-detect currently connected SSID as default Target SSID
set "DETECTED_SSID="
for /f "delims=" %%s in ('python -c "from network_diagnostics import get_active_wifi_interface; print(get_active_wifi_interface().get('ssid',''))" 2^>nul') do set "DETECTED_SSID=%%s"

:: 1. Collect Job Details
:ASK_JOB
set "JOB_NAME="
set /p JOB_NAME="[?] Enter Client or Job Name (e.g. Fagan, Biller_Site): "
if not defined JOB_NAME (
    echo [-] Job name is required. Please enter a valid name.
    goto ASK_JOB
)

:: Sanitize job name for safe Windows folder path
for /f "delims=" %%c in ('python -c "import os, re; s = re.sub(r'[^A-Za-z0-9_-]+', '_', os.environ.get('JOB_NAME', '')).strip('_'); print(s or 'Job')"') do set "CLEAN_JOB=%%c"

set "TECH_NAME="
set /p TECH_NAME="[?] Enter Field Technician Name or ID: "
if not defined TECH_NAME set TECH_NAME=Field_Tech

set "TARGET_SSID="
if defined DETECTED_SSID (
    set /p TARGET_SSID="[?] Enter Target SSID (Press Enter for '!DETECTED_SSID!'): "
    if not defined TARGET_SSID set "TARGET_SSID=!DETECTED_SSID!"
) else (
    set /p TARGET_SSID="[?] Enter Target SSID (e.g. HomeWifi1, or press Enter for ALL): "
)

set "SITE_NOTES="
set /p SITE_NOTES="[?] Enter any Site Notes or Complaints (optional, press Enter to skip): "

:: Generate Timestamp (YYYYMMDD_HHMMSS) via Python (faster than spawning PowerShell)
for /f %%a in ('python -c "from datetime import datetime; print(datetime.now().strftime('%%Y%%m%%d_%%H%%M%%S'))"') do set "STAMP=%%a"

set "JOB_FOLDER=%~dp0Jobs\%CLEAN_JOB%_%STAMP%"
if not exist "%JOB_FOLDER%" mkdir "%JOB_FOLDER%"

echo.
echo [+] Created Job Package Folder:
echo     %JOB_FOLDER%
echo.

:: Save Metadata JSON using Python environment variables for safe special-character handling
python -c "import json, os; meta = {'job_name': os.environ.get('JOB_NAME',''), 'tech_name': os.environ.get('TECH_NAME',''), 'target_ssid': os.environ.get('TARGET_SSID',''), 'notes': os.environ.get('SITE_NOTES',''), 'date': os.environ.get('STAMP','')}; f_path = os.path.join(os.environ['JOB_FOLDER'], 'job_meta.json'); f = open(f_path, 'w', encoding='utf-8'); json.dump(meta, f, indent=2); f.close()"

:: ===============================================================================
:: STEP 1: Hardware, Baseline RF Scan & Cloudflare Speedtest
:: ===============================================================================
echo -------------------------------------------------------------------------------
echo [STEP 1/4] Hardware Check, Live RF Baseline ^& Cloudflare Speedtest...
echo -------------------------------------------------------------------------------
netsh wlan show interfaces > "%JOB_FOLDER%\wlan_interfaces.txt"
netsh wlan show drivers > "%JOB_FOLDER%\wlan_drivers.txt"
echo [+] Saved Wi-Fi adapter driver and interface profile.

echo [*] Triggering live hardware RF scan (2.4 / 5 / 6 GHz)...
python "%~dp0survey_scanner.py" --scan > "%JOB_FOLDER%\baseline_rf_scan.txt"
echo [+] Baseline RF scan recorded.

echo [*] Running Baseline Split-Hop Ping ^& Cloudflare Speedtest (with Bufferbloat)...
python "%~dp0network_diagnostics.py" --speedtest --ping --waypoint "Baseline" --out-json "%JOB_FOLDER%\speedtest_results.json"
echo.

:: ===============================================================================
:: STEP 2: Interactive Room-by-Room Waypoint Walk
:: ===============================================================================
echo -------------------------------------------------------------------------------
echo [STEP 2/4] Site Walkthrough - Room-by-Room Waypoint ^& Link Logging
echo -------------------------------------------------------------------------------
echo  INSTRUCTIONS FOR FIELD TECH:
echo   1. Walk into a room or coverage zone (e.g. Living Room, Office, Basement TV).
echo   2. Stand stationary for 3-5 seconds.
echo   3. Type the room name below and press Enter.
echo      TIP: Add '*' to the end of a room name (e.g. Office*) to also run a
echo           Cloudflare Speedtest in that specific room!
echo   4. When you have surveyed all locations, type 'DONE'.
echo -------------------------------------------------------------------------------
echo.

:WAYPOINT_LOOP
set "WAYPOINT="
set /p WAYPOINT="[?] Enter Location/Room Name (append * for speedtest, or 'DONE' to finish): "
if /i "%WAYPOINT%"=="DONE" goto FINISH_WAYPOINTS
if not defined WAYPOINT (
    echo [-] Location name cannot be empty. Please enter a room name or 'DONE'.
    goto WAYPOINT_LOOP
)

echo [*] Recording live RF signals, active link speed, and Gateway/WAN ping at '%WAYPOINT%'...
python "%~dp0survey_scanner.py" --waypoint "%WAYPOINT%" --out "%JOB_FOLDER%\survey_waypoints.csv"
echo [+] Saved '%WAYPOINT%'. Move to the next room.
echo.
goto WAYPOINT_LOOP

:FINISH_WAYPOINTS
echo.
echo [+] Waypoint survey completed. Data logged to survey_waypoints.csv ^& waypoint_telemetry.csv.
echo.

:: ===============================================================================
:: STEP 3: 802.11 Packet Capture (TShark Auto-Detect Wi-Fi)
:: ===============================================================================
echo -------------------------------------------------------------------------------
echo [STEP 3/4] Wi-Fi Packet Capture (TShark)
echo -------------------------------------------------------------------------------
if not exist "C:\Program Files\Wireshark\tshark.exe" (
    echo [!] Wireshark / TShark not detected at "C:\Program Files\Wireshark\tshark.exe".
    echo     Skipping Step 3 packet capture ^(optional^).
    goto SKIP_CAPTURE
)
set "DO_CAP="
set /p DO_CAP="[?] Run Wi-Fi Packet Capture now? (Y/N, default Y): "
if /i "%DO_CAP%"=="N" goto SKIP_CAPTURE

set "CAP_DUR="
set /p CAP_DUR="[?] Enter capture duration in seconds (Default 30): "
if not defined CAP_DUR set CAP_DUR=30

echo [*] Capturing frames on auto-detected Wi-Fi interface for %CAP_DUR% seconds...
python "%~dp0capture_packets.py" -i auto -d %CAP_DUR% -o "%JOB_FOLDER%\%CLEAN_JOB%_rf_beacons.pcapng"

:SKIP_CAPTURE
echo.

:: ===============================================================================
:: STEP 4: Fast Local LAN Discovery Sweep & OUI Inventory
:: ===============================================================================
echo -------------------------------------------------------------------------------
echo [STEP 4/4] Local LAN Subnet Sweep ^& Hardware OUI Discovery
echo -------------------------------------------------------------------------------
set "DO_LAN="
set /p DO_LAN="[?] Are you connected to the client LAN or Wi-Fi? (Y/N, default Y): "
if /i not "%DO_LAN%"=="N" (
    python "%~dp0network_diagnostics.py" --lan-sweep "%JOB_FOLDER%"
) else (
    echo [-] Skipped LAN audit - technician not connected to local network.
)
echo.

:: ===============================================================================
:: Packaging and Engineering + PM HTML Summary
:: ===============================================================================
echo ===============================================================================
echo               GENERATING ENGINEERING ^& PM HAND-OFF REPORTS
echo ===============================================================================
python "%~dp0generate_job_summary.py" "%JOB_FOLDER%"
echo.

echo ===============================================================================
echo                          SITE SURVEY COMPLETE
echo ===============================================================================
echo  All job deliverables (including PM_SITE_SURVEY_REPORT.html) are saved to:
echo  %JOB_FOLDER%
echo ===============================================================================
echo.

start "" explorer.exe "%JOB_FOLDER%"
pause
