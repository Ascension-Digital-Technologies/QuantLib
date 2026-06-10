@echo off
setlocal
set ROOT=%~dp0..\..
pushd "%ROOT%" >nul
set BUILD=build-release-check
cmake -S . -B "%BUILD%" -DCMAKE_BUILD_TYPE=Release -DQUANTLIB_BUILD_TESTS=ON -DQUANTLIB_BUILD_BENCHES=ON -DQUANTLIB_BUILD_EXAMPLES=ON -DQUANTLIB_ENABLE_HARDENING=ON || goto fail
cmake --build "%BUILD%" --config Release || goto fail
ctest --test-dir "%BUILD%" --output-on-failure || goto fail
if exist "%BUILD%\Release\quantlib-inspect.exe" (set INSPECT=%BUILD%\Release\quantlib-inspect.exe) else (set INSPECT=%BUILD%\quantlib-inspect.exe)
"%INSPECT%" --selftest || goto fail
"%INSPECT%" --release || goto fail
"%INSPECT%" --inventory || goto fail
"%INSPECT%" --stable-api || goto fail
"%INSPECT%" --production-ready || goto fail

popd >nul
exit /b 0
:fail
popd >nul
exit /b 1
