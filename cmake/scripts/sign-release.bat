@echo off
setlocal
set ROOT=%~dp0..\..
pushd "%ROOT%" >nul
if "%1"=="" goto usage
echo Signing scaffold for %1
echo Use your release signing system. Do not store private signing keys in this repository.
echo Example: gpg --detach-sign --armor "%1"
goto done
:usage
echo artifact path required
goto fail
:done

popd >nul
exit /b 0
:fail
popd >nul
exit /b 1
