@echo off
setlocal EnableExtensions
cd /d "%~dp0"

REM ---------------------------------------------------------------------------
REM Local development launcher. Binds loopback only, which is the one case where
REM the server still permits plain HTTP. For anything reachable from another
REM machine, supply a TLS certificate or put it behind a reverse proxy.
REM ---------------------------------------------------------------------------

if "%SURGE_ADMIN_USER%"=="" set "SURGE_ADMIN_USER=admin"
if "%SURGE_ADMIN_PASSWORD%"=="" (
  echo [ERROR] SURGE_ADMIN_PASSWORD is not set.
  echo         Set it before starting. Do not ship a default administrator password.
  pause
  exit /b 1
)
if "%SURGE_LICENSE_SECRET%"=="" (
  echo [ERROR] SURGE_LICENSE_SECRET is not set. Generate one and set it in your environment.
  pause
  exit /b 1
)

set "SURGE_LICENSE_URL=http://127.0.0.1:5077"
set "ASPNETCORE_URLS=%SURGE_LICENSE_URL%"

set "OUT=%~dp0publish\SurgeServer"
set "EXE=%OUT%\Surge.LicenseServer.exe"
if not exist "%EXE%" (
  echo [INFO] Publishing License Server...
  dotnet publish "%~dp0Surge.LicenseServer\Surge.LicenseServer.csproj" -c Release -r win-x64 --self-contained true -o "%OUT%"
  if errorlevel 1 (
    echo [ERROR] Publish failed.
    pause
    exit /b 1
  )
)

echo ==============================================
echo   SURGE LICENSE SERVER (local development)
echo   Bind: %SURGE_LICENSE_URL%
echo ==============================================
echo [INFO] Keep this window open.
echo.
"%EXE%"
set "EXITCODE=%ERRORLEVEL%"
echo.
echo [INFO] Server exited with code %EXITCODE%.
pause
exit /b %EXITCODE%
