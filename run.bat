@echo off
title Mini IDS - Network Intrusion Detection System
echo Starting Mini IDS GUI...
python gui.py
if errorlevel 1 (
    echo.
    echo ERROR: Python not found or there was an error.
    echo Make sure Python 3.8+ is installed.
    pause
)
