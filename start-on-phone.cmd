@echo off
cd /d "%~dp0"
where node >nul 2>nul
if errorlevel 1 (
  echo Node.js is required. Install the current LTS version from https://nodejs.org then run this file again.
  pause
  exit /b 1
)
echo Starting Dar Al-Salam nursery app...
echo Keep this window open while using the app.
echo The app will print the computer and phone addresses below.
node server.mjs
pause
