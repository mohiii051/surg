@echo off
REM ---------------------------------------------------------------------------
REM Surge v19.4.1 - deterministic Windows publish (Client + Admin Panel)
REM Requires the .NET 8 SDK pinned in global.json (8.0.425 or later 8.0.x feature band).
REM ---------------------------------------------------------------------------
setlocal
cd /d "%~dp0"

echo === Surge Client (win-x64, self-contained, single file) ===
dotnet publish SurgeApp.csproj ^
  -c Release ^
  -r win-x64 ^
  --self-contained true ^
  -p:PublishSingleFile=true ^
  -p:IncludeNativeLibrariesForSelfExtract=true ^
  -p:EnableCompressionInSingleFile=true ^
  -p:DebugType=portable ^
  -p:Deterministic=true ^
  -p:ContinuousIntegrationBuild=true ^
  -o publish\client
if errorlevel 1 goto :fail

echo === Surge Admin Panel (win-x64, self-contained, single file) ===
dotnet publish Surge.AdminPanel\Surge.AdminPanel.csproj ^
  -c Release ^
  -r win-x64 ^
  --self-contained true ^
  -p:PublishSingleFile=true ^
  -p:IncludeNativeLibrariesForSelfExtract=true ^
  -p:DebugType=portable ^
  -p:Deterministic=true ^
  -p:ContinuousIntegrationBuild=true ^
  -o publish\admin
if errorlevel 1 goto :fail

echo.
echo PUBLISH SUCCESS (v19.4.1)
echo   publish\client\Surge.exe
echo   publish\admin\Surge.AdminPanel.exe
echo.
echo Both EXEs are UNSIGNED. See RELEASE.md "Code signing" before distribution.
goto :eof

:fail
echo.
echo PUBLISH FAILED - see the errors above.
exit /b 1
