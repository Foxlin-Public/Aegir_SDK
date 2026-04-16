@echo off
setlocal
powershell -ExecutionPolicy Bypass -File "%~dp0scripts\local-maven.ps1" %*
exit /b %ERRORLEVEL%
