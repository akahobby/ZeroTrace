@echo off
setlocal EnableExtensions
title ZeroTrace

REM =========================
REM Config
REM =========================
set "ZT_DIR=C:\ProgramData\ZeroTrace"
set "ZT_ENGINE=%ZT_DIR%\ZeroTrace-Engine.ps1"
set "ZT_LOGS=%ZT_DIR%\Logs"
set "ZT_URL=https://raw.githubusercontent.com/akahobby/ZeroTrace/main/ZeroTrace-Engine.ps1"

REM =========================
REM ANSI ESC
REM =========================
for /f "delims=" %%A in ('echo prompt $E^| cmd') do set "ESC=%%A"
set "R=%ESC%[0m"
set "B=%ESC%[1m"
set "C_CYAN=%ESC%[96m"
set "C_BLUE=%ESC%[94m"
set "C_GREEN=%ESC%[92m"
set "C_YELLOW=%ESC%[93m"
set "C_RED=%ESC%[91m"
set "C_GRAY=%ESC%[90m"
set "C_WHITE=%ESC%[97m"

REM =========================
REM Ensure folders
REM =========================
if not exist "%ZT_DIR%"  mkdir "%ZT_DIR%" >nul 2>&1
if not exist "%ZT_LOGS%" mkdir "%ZT_LOGS%" >nul 2>&1

REM =========================
REM Elevate if needed
REM =========================
net session >nul 2>&1
if %errorlevel% neq 0 (
  powershell -NoProfile -ExecutionPolicy Bypass -Command ^
    "Start-Process -FilePath $env:ComSpec -Verb RunAs -ArgumentList '/c','""%~f0""'"
  exit /b
)

REM =========================
REM Download engine only if missing
REM =========================
if not exist "%ZT_ENGINE%" call :DownloadEngine

:MENU
cls
call :Header

echo.
echo %C_CYAN%  [1]%R% %C_WHITE%Scan Only%R% %C_GRAY%(safe preview; no changes)%R%
echo %C_YELLOW%  [2]%R% %C_WHITE%Live Cleanup%R% %C_GRAY%(makes changes after confirmation)%R%
echo.
echo %C_BLUE%  [3]%R% %C_WHITE%Open Logs Folder%R%
echo %C_BLUE%  [4]%R% %C_WHITE%Force Update Engine%R% %C_GRAY%(re-download latest)%R%
echo.
echo %C_RED%  [0]%R% %C_WHITE%Exit%R%
echo.
set /p "CHOICE=%C_GRAY%Choose%R% %C_GRAY%>%R% "

if "%CHOICE%"=="1" goto RUN_SCAN
if "%CHOICE%"=="2" goto RUN_LIVE
if "%CHOICE%"=="3" (start "" "%ZT_LOGS%" & goto MENU)
if "%CHOICE%"=="4" goto FORCE_UPDATE
if "%CHOICE%"=="0" exit /b
goto MENU

:RUN_SCAN
cls
call :Header
echo %C_GRAY%Launching engine in%R% %C_GREEN%SCAN-ONLY%R% %C_GRAY%mode...%R%
echo.
powershell.exe -NoProfile -ExecutionPolicy Bypass -File "%ZT_ENGINE%" -LogDir "%ZT_LOGS%" -ScanOnly
echo.
echo %C_GRAY%Press any key to return to menu...%R%
pause >nul
goto MENU

:RUN_LIVE
cls
call :Header
echo %C_GRAY%Launching engine in%R% %C_YELLOW%LIVE%R% %C_GRAY%mode...%R%
echo.
powershell.exe -NoProfile -ExecutionPolicy Bypass -File "%ZT_ENGINE%" -LogDir "%ZT_LOGS%"
echo.
echo %C_GRAY%Press any key to return to menu...%R%
pause >nul
goto MENU

:FORCE_UPDATE
cls
call :Header
echo %C_GRAY%Forcing engine update...%R%
del /f /q "%ZT_ENGINE%" >nul 2>&1
call :DownloadEngine
echo.
echo %C_GRAY%Press any key to return to menu...%R%
pause >nul
goto MENU

:DownloadEngine
echo %C_GRAY%Downloading engine from GitHub...%R%
powershell -NoProfile -ExecutionPolicy Bypass -Command ^
  "try { Invoke-WebRequest -Uri '%ZT_URL%' -OutFile '%ZT_ENGINE%' -UseBasicParsing } catch { exit 1 }"
if not exist "%ZT_ENGINE%" (
  echo %C_RED%Failed to download engine.%R%
  echo %C_GRAY%Check your internet or the raw URL.%R%
  pause
  exit /b
)
exit /b

:Header
echo %C_CYAN%============================================================%R%
echo %C_CYAN%   %B%ZeroTrace%R% %C_GRAY% - Launcher%R%
echo %C_CYAN%============================================================%R%
echo %C_GRAY%  Engine:%R% %C_WHITE%%ZT_ENGINE%%R%
echo %C_GRAY%  Logs  :%R% %C_WHITE%%ZT_LOGS%%R%
exit /b
