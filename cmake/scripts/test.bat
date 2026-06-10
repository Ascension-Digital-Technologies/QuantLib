@echo off
setlocal
set ROOT=%~dp0..\..
pushd "%ROOT%" >nul
set BUILD=%1
if "%BUILD%"=="" set BUILD=build
cmake -S . -B "%BUILD%" -DCMAKE_BUILD_TYPE=Release -DQUANTLIB_ENABLE_HARDENING=ON || goto fail
cmake --build "%BUILD%" --config Release || goto fail
ctest --test-dir "%BUILD%" --output-on-failure || goto fail
echo Tests completed successfully.

popd >nul
exit /b 0
:fail
popd >nul
exit /b 1
