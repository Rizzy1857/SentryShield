@echo off
REM SentryShield Smart Launcher Wrapper
REM This simply bypasses execution policy to launch the PowerShell script seamlessly.

pushd "%~dp0"
powershell -ExecutionPolicy Bypass -File "build_and_run.ps1" %*
pause
popd
