@echo off
setlocal enabledelayedexpansion

echo ============================================================
echo   Instalador y Desplegador - Scan de Puertos y Seguridad
echo ============================================================
echo.

:: Verificar si Docker está instalado
docker --version >nul 2>&1
if %errorlevel% equ 0 (
    echo [+] Se detecto Docker instalado.
    set /p use_docker="¿Deseas desplegar la herramienta usando Docker? (s/n): "
    if /i "!use_docker!"=="s" (
        echo [+] Construyendo y ejecutando imagen Docker...
        docker build -t scanner-seguridad .
        echo.
        echo [!] Nota: El escaneo de puertos locales mostrara procesos DENTRO del contenedor.
        echo [!] Se recomienda el uso local para auditoria completa del host.
        docker run -it --name scanner-container scanner-seguridad
        goto :end
    )
) else (
    echo [-] Docker no detectado. Procediendo con instalacion local...
)

:: Instalacion Local
echo [+] Verificando entorno Python...
python --version >nul 2>&1
if %errorlevel% neq 0 (
    echo [!] Error: Python no esta instalado o no esta en el PATH.
    pause
    exit /b 1
)

if not exist .venv (
    echo [+] Creando entorno virtual...
    python -m venv .venv
)

echo [+] Instalando dependencias...
call .venv\\Scripts\\activate
pip install -r requirements.txt

echo.
echo [+] Instalacion completada con exito.
set /p run_now="¿Deseas ejecutar el diagnóstico completo ahora? (Requiere Admin) (s/n): "
if /i "!run_now!"=="s" (
    echo [+] Iniciando run_full_diagnostic.py...
    python run_full_diagnostic.py
)

:end
echo.
echo Presiona cualquier tecla para salir.
pause >nul
