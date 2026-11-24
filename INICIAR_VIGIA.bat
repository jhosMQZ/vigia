@echo off
rem ============================================================================
rem  Vigía - inicio en Windows (doble clic).
rem  Prepara el entorno la primera vez, arranca Vigía SOLO en este equipo
rem  (http://127.0.0.1:8600) y abre el navegador. No necesita administrador,
rem  no guarda ni muestra secretos y no inicia ningún análisis.
rem  Para detenerlo: Ctrl+C en esta ventana o DETENER_VIGIA.bat.
rem ============================================================================
setlocal EnableExtensions DisableDelayedExpansion
if not "%OS%"=="Windows_NT" (
  echo Este archivo solo funciona en Windows.
  exit /b 1
)
chcp 65001 >nul
title Vigía
set "PYTHONUTF8=1"
set "PYTHONIOENCODING=utf-8"

set "ROOT=%~dp0"
if "%ROOT:~-1%"=="\" set "ROOT=%ROOT:~0,-1%"
cd /d "%ROOT%" || (echo No se pudo abrir la carpeta de Vigía. & goto :fallo)
if not exist "%ROOT%\backend\vigia\launcher.py" (
  echo No se encuentra el código de Vigía junto a este archivo.
  echo Ejecuta INICIAR_VIGIA.bat desde la carpeta raíz del proyecto.
  goto :fallo
)

echo.
echo  Vigía - preparando el inicio
echo  ----------------------------
set "VENV=%ROOT%\.venv"
set "VPY=%VENV%\Scripts\python.exe"

if exist "%VPY%" (
  "%VPY%" -c "import sys; sys.exit(0 if sys.version_info >= (3, 11) else 1)" >nul 2>&1
  if errorlevel 1 (
    echo El entorno virtual .venv existe pero no funciona o usa un Python anterior a 3.11.
    echo Renombra la carpeta .venv y vuelve a ejecutar este archivo para crear uno nuevo.
    goto :fallo
  )
  echo Entorno virtual: encontrado.
  goto :entorno_listo
)

call :buscar_python
if errorlevel 1 goto :fallo
echo Creando el entorno virtual en .venv ...
%PYCMD% -m venv "%VENV%"
if errorlevel 1 (
  echo No se pudo crear el entorno virtual con %PYCMD%.
  goto :fallo
)
if not exist "%VPY%" (
  echo El entorno virtual no se creó correctamente.
  goto :fallo
)

:entorno_listo
call "%VENV%\Scripts\activate.bat"
pushd "%ROOT%\backend"
"%VPY%" -m vigia.launcher prepare
if errorlevel 1 (
  popd
  goto :fallo
)
"%VPY%" -m vigia.launcher start %*
set "RC=%ERRORLEVEL%"
popd
if "%RC%"=="0" goto :fin
if "%RC%"=="10" goto :fin
goto :fallo

rem ---------------------------------------------------------------------------
rem Busca un Python 3.11 o superior: VIGIA_PYTHON, el lanzador py, python del
rem PATH (ignorando el acceso directo de Microsoft Store) y, si existe, uv.
:buscar_python
set "PYCMD="
set "PYCHECK=import sys; sys.exit(0 if sys.version_info >= (3, 11) else 1)"
if defined VIGIA_PYTHON (
  "%VIGIA_PYTHON%" -c "%PYCHECK%" >nul 2>&1 && (set PYCMD="%VIGIA_PYTHON%" & goto :python_ok)
  echo VIGIA_PYTHON no apunta a un Python 3.11 o superior; se buscan otros.
)
for %%V in (3.13 3.12 3.11) do (
  py -%%V -c "%PYCHECK%" >nul 2>&1 && (set "PYCMD=py -%%V" & goto :python_ok)
)
python -c "%PYCHECK%" >nul 2>&1 && (set "PYCMD=python" & goto :python_ok)
python3 -c "%PYCHECK%" >nul 2>&1 && (set "PYCMD=python3" & goto :python_ok)
for /f "delims=" %%P in ('uv python find --system "3.12" 2^>nul') do (
  "%%P" -c "%PYCHECK%" >nul 2>&1 && (set PYCMD="%%P" & goto :python_ok)
)
echo.
echo No se encontró Python 3.11 o superior.
echo Instálalo desde https://www.python.org/downloads/ (marca "Add python.exe to PATH")
echo y vuelve a ejecutar este archivo. También puedes indicar su ruta en VIGIA_PYTHON.
exit /b 1
:python_ok
echo Python encontrado: %PYCMD%
exit /b 0

:fallo
echo.
echo Vigía no se ha iniciado. Revisa el mensaje anterior.
if not defined VIGIA_NO_PAUSE pause
endlocal
exit /b 1

:fin
echo.
if not defined VIGIA_NO_PAUSE pause
endlocal
exit /b 0
