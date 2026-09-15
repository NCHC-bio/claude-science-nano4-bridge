@echo off
REM Double-click to bring the nano4 bridge up.
REM Answer the 2FA prompts once; leave this window open while you work.
cd /d "%~dp0"
uv run nano4_sshd.py %*
echo.
echo [bridge stopped] press any key to close
pause >nul
