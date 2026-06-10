@echo off
setlocal
set ROOT=%~dp0..\..
pushd "%ROOT%" >nul
set BIN=%1
if "%BIN%"=="" set BIN=build\quantlib-inspect.exe
set OUT=%2
if "%OUT%"=="" set OUT=SBOM.txt
"%BIN%" --sbom > "%OUT%" || goto fail
echo wrote %OUT%

popd >nul
exit /b 0
:fail
popd >nul
exit /b 1
