@echo off
setlocal
set ROOT=%~dp0..\..
pushd "%ROOT%" >nul
set BIN_DIR=%1
if "%BIN_DIR%"=="" set BIN_DIR=build
if exist "%BIN_DIR%\Release\quantlib-inspect.exe" (set INSPECT=%BIN_DIR%\Release\quantlib-inspect.exe) else (set INSPECT=%BIN_DIR%\quantlib-inspect.exe)
"%INSPECT%" --version || goto fail
"%INSPECT%" --selftest || goto fail
"%INSPECT%" --release || goto fail
"%INSPECT%" --inventory || goto fail
"%INSPECT%" --ops || goto fail
"%INSPECT%" --runbook >nul || goto fail

popd >nul
exit /b 0
:fail
popd >nul
exit /b 1
