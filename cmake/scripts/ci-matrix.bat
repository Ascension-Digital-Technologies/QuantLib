@echo off
setlocal
set ROOT=%~dp0..\..
pushd "%ROOT%" >nul
set BUILD=build-ci
cmake -S . -B "%BUILD%" -DQUANTLIB_BUILD_EXAMPLES=ON -DQUANTLIB_ENABLE_HARDENING=ON || goto fail
cmake --build "%BUILD%" --config Release || goto fail
ctest --test-dir "%BUILD%" --output-on-failure || goto fail
if exist "%BUILD%\Release\quantlib-inspect.exe" (set INSPECT=%BUILD%\Release\quantlib-inspect.exe) else (set INSPECT=%BUILD%\quantlib-inspect.exe)
"%INSPECT%" --selftest || goto fail
"%INSPECT%" --release || goto fail
"%INSPECT%" --test-infra || goto fail

popd >nul
exit /b 0
:fail
popd >nul
exit /b 1
