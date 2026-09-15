@echo off
REM Double-click this. First run sets everything up; after that it just logs in.
cd /d "%~dp0"
powershell -NoProfile -ExecutionPolicy Bypass -File "%~dp0bridge.ps1" %*
