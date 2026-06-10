@echo off
setlocal
set ROOT=%~dp0..\..
pushd "%ROOT%" >nul
set BUILD=build-package
set PREFIX=package-root
cmake -S . -B "%BUILD%" -DQUANTLIB_BUILD_EXAMPLES=ON -DQUANTLIB_ENABLE_HARDENING=ON || goto fail
cmake --build "%BUILD%" --config Release || goto fail
cmake --install "%BUILD%" --config Release --prefix "%PREFIX%" || goto fail
"%PREFIX%\bin\quantlib-inspect.exe" --version || goto fail
"%PREFIX%\bin\quantlib-inspect.exe" --selftest || goto fail

popd >nul
exit /b 0
:fail
popd >nul
exit /b 1
