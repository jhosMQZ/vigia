@echo off
rem ============================================================================
rem  Vigía - detención ordenada.
rem  Detiene solo la instancia iniciada con INICIAR_VIGIA.bat (se comprueba el
rem  proceso por PID, hora de inicio y orden de arranque). No cierra otros
rem  programas ni procesos de Windows.
rem ============================================================================
setlocal EnableExtensions DisableDelayedExpansion
chcp 65001 >nul
set "PYTHONUTF8=1"
set "PYTHONIOENCODING=utf-8"
set "ROOT=%~dp0"
if "%ROOT:~-1%"=="\" set "ROOT=%ROOT:~0,-1%"
set "VPY=%ROOT%\.venv\Scripts\python.exe"
if not exist "%VPY%" (
  echo Vigía no está preparado en esta carpeta: no hay nada que detener.
  if not defined VIGIA_NO_PAUSE pause
  exit /b 0
)
pushd "%ROOT%\backend"
"%VPY%" -m vigia.launcher stop
set "RC=%ERRORLEVEL%"
popd
if not defined VIGIA_NO_PAUSE pause
endlocal & exit /b %RC%
