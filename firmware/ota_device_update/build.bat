@echo off
setlocal EnableDelayedExpansion
rem ===========================================================================
rem  build.bat  --  compile, upload and monitor ota_device_update on ESP32-S3
rem
rem  Usage:
rem    build.bat              compile + upload + monitor (port auto-detected)
rem    build.bat COM5         compile + upload + monitor on COM5
rem    build.bat COM5 compile only compile
rem    build.bat - compile    only compile (no port needed)
rem    build.bat COM5 upload  compile + upload
rem    build.bat COM5 monitor only open the serial monitor
rem
rem  Every compile also copies the OTA image to
rem    ..\release\ota_device_update_<FW_VERSION>.bin
rem  -- upload that file on the OTA dashboard with the same version string.
rem ===========================================================================

set "FQBN=esp32:esp32:esp32s3:USBMode=hwcdc,CDCOnBoot=cdc,FlashMode=qio,FlashSize=16M,PartitionScheme=app3M_fat9M_16MB,PSRAM=opi"
set "BAUD=115200"
rem Sketch folder = folder of this batch file (without trailing backslash).
set "SKETCH=%~dp0."
rem Build outside OneDrive so sync does not lock the build files.
set "BUILD=%TEMP%\ota_device_update_s3_build"
for %%R in ("%~dp0..\release") do set "RELEASE=%%~fR"

set "PORT=%~1"
if "%PORT%"=="-" set "PORT="
set "MODE=%~2"
if "%MODE%"=="" set "MODE=all"

where arduino-cli >nul 2>&1
if errorlevel 1 (
  echo [ERROR] arduino-cli not found in PATH.
  goto :fail
)

if /i "%MODE%"=="monitor" goto :detect

rem -- Compile ----------------------------------------------------------------
echo.
echo [1/3] Compiling %SKETCH%
arduino-cli compile --fqbn "%FQBN%" --build-path "%BUILD%" "%SKETCH%"
if errorlevel 1 (
  echo [ERROR] Compile failed.
  goto :fail
)

rem -- Release copy: name the OTA image after FW_VERSION in config.h ----------
set "FWVER="
for /f "tokens=3" %%V in ('findstr /r /c:"^#define  *FW_VERSION " "%SKETCH%\config.h"') do set "FWVER=%%~V"
if "%FWVER%"=="" (
  echo [WARN] FW_VERSION not found in config.h - release copy skipped.
) else (
  if not exist "%RELEASE%" mkdir "%RELEASE%"
  copy /y "%BUILD%\ota_device_update.ino.bin" "%RELEASE%\ota_device_update_%FWVER%.bin" >nul
  if errorlevel 1 (
    echo [WARN] Could not copy the .bin to %RELEASE%
  ) else (
    echo.
    echo OTA image: %RELEASE%\ota_device_update_%FWVER%.bin
    echo Upload it on the dashboard as version %FWVER%
  )
)
if /i "%MODE%"=="compile" goto :done

:detect
rem -- Find the port ----------------------------------------------------------
rem Prefer a port reported as ESP32, then any USB serial port.
if "%PORT%"=="" (
  for /f "tokens=1" %%P in ('arduino-cli board list ^| findstr /b /r "COM[0-9]" ^| findstr /i "ESP32"') do (
    if "!PORT!"=="" set "PORT=%%P"
  )
)
if "%PORT%"=="" (
  for /f "tokens=1" %%P in ('arduino-cli board list ^| findstr /b /r "COM[0-9]" ^| findstr /i "USB"') do (
    if "!PORT!"=="" set "PORT=%%P"
  )
)
if "%PORT%"=="" (
  echo [ERROR] No COM port found. Connect the board or pass the port: build.bat COM5
  goto :fail
)
echo Using port %PORT%
if /i "%MODE%"=="monitor" goto :monitor

rem -- Upload -----------------------------------------------------------------
echo.
echo [2/3] Uploading to %PORT%
arduino-cli upload -p %PORT% --fqbn "%FQBN%" --input-dir "%BUILD%" "%SKETCH%"
if errorlevel 1 (
  echo [ERROR] Upload failed. Hold BOOT, tap RESET, release BOOT, then try again.
  goto :fail
)
if /i "%MODE%"=="upload" goto :done

rem USB CDC port re-enumerates after reset; give Windows a moment.
timeout /t 3 /nobreak >nul

:monitor
rem -- Monitor ----------------------------------------------------------------
echo.
echo [3/3] Serial monitor on %PORT% at %BAUD% baud. Press Ctrl+C to exit.
arduino-cli monitor -p %PORT% -c baudrate=%BAUD%
goto :done

:fail
echo.
rem Keep the window open on errors (set NOPAUSE=1 for scripted use).
if not defined NOPAUSE pause
endlocal
exit /b 1

:done
endlocal
exit /b 0
