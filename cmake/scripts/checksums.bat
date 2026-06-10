@echo off
setlocal
set ROOT=%~dp0..\..
pushd "%ROOT%" >nul
set TARGET=%1
if "%TARGET%"=="" set TARGET=.
set OUT=%2
if "%OUT%"=="" set OUT=SHA256SUMS.txt
powershell -NoProfile -ExecutionPolicy Bypass -Command "Get-ChildItem -Path %TARGET% -Recurse -File | Sort-Object FullName | ForEach-Object { $h=Get-FileHash -Algorithm SHA256 $_.FullName; "$($h.Hash.ToLower())  $($_.FullName)" } | Set-Content %OUT%" || goto fail
echo wrote %OUT%

popd >nul
exit /b 0
:fail
popd >nul
exit /b 1
