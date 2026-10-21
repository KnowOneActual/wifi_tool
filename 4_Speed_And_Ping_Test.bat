@echo off
title Cloudflare Speedtest, Bufferbloat & Split-Hop Ping
color 0B
echo ===============================================================================
echo      CLOUDFLARE SPEEDTEST + BUFFERBLOAT + GATEWAY vs. WAN PING AUDIT
echo ===============================================================================
echo.
python "%~dp0network_diagnostics.py" --speedtest --ping
echo.
echo ===============================================================================
pause
