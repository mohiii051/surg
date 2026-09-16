@echo off
setlocal EnableExtensions
cd /d "%~dp0"

REM The client refuses any non-loopback http:// endpoint. Point this at your TLS host.
if "%SURGE_API_URL%"=="" set "SURGE_API_URL=http://95.38.233.67/"

set "OUT=%~dp0publish\Surge"
set "EXE=%OUT%\Surge.exe"
if not exist "%EXE%" (
  echo [INFO] Publishing Surge Client...
  dotnet publish "%~dp0SurgeApp.csproj" -c Release -r win-x64 --self-contained true -o "%OUT%"
  if errorlevel 1 (
    echo [ERROR] Publish failed.
    pause
    exit /b 1
  )
)
echo [INFO] Starting: "%EXE%"
echo [INFO] API: %SURGE_API_URL%
pushd "%OUT%"
"%EXE%"
set "RC=%ERRORLEVEL%"
popd
if not "%RC%"=="0" (
  echo.
  echo [ERROR] Surge Client exited with code %RC%.
  echo Check the startup log for details.
  pause
  exit /b %RC%
)
endlocal
exit /b 0
