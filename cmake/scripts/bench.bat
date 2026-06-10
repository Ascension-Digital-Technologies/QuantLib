@echo off
setlocal
set ROOT=%~dp0..\..
pushd "%ROOT%" >nul
set BUILD=%1
if "%BUILD%"=="" set BUILD=build
set ITERS=%2
if "%ITERS%"=="" set ITERS=100000
cmake -S . -B "%BUILD%" -DCMAKE_BUILD_TYPE=Release -DQUANTLIB_BUILD_BENCHES=ON || goto fail
cmake --build "%BUILD%" --target quantlib-bench --config Release || goto fail
if exist "%BUILD%\Release\quantlib-bench.exe" ("%BUILD%\Release\quantlib-bench.exe" %ITERS%) else ("%BUILD%\quantlib-bench.exe" %ITERS%)
if errorlevel 1 goto fail

popd >nul
exit /b 0
:fail
popd >nul
exit /b 1
