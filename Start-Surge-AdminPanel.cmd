@echo off
setlocal EnableExtensions
cd /d "%~dp0"

REM The Admin Panel intentionally uses the public HTTP endpoint for this deployment.
if "%SURGE_API_URL%"=="" set "SURGE_API_URL=http://95.38.233.67/"

set "OUT=%~dp0publish\SurgeAdmin"
set "EXE=%OUT%\Surge.AdminPanel.exe"
if not exist "%EXE%" (
  echo [INFO] Publishing Surge Admin Panel...
  dotnet publish "%~dp0Surge.AdminPanel\Surge.AdminPanel.csproj" -c Release -r win-x64 --self-contained true -o "%OUT%"
  if errorlevel 1 (
    echo [ERROR] Publish failed.
    pause
    exit /b 1
  )
)
echo [INFO] Starting: "%EXE%"
start "SURGE Admin Panel" /D "%OUT%" "%EXE%"
if errorlevel 1 (
  echo [ERROR] Windows could not launch the Admin Panel EXE.
  pause
  exit /b 1
)
endlocal
exit /b 0
