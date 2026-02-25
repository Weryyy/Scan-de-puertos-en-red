# 🕵️‍♂️ Escáner de Puertos y Respuesta ante Incidentes (EDR-Lite)

Este proyecto ha evolucionado de un simple escáner a una herramienta integral de **Detección y Respuesta (EDR)** para redes locales y sistemas Windows/Linux. Utiliza inteligencia de amenazas basada en estándares industriales como **YARA** para identificar, analizar y mitigar vulnerabilidades.

## 🚀 Funcionalidades Principales

*   **🔍 Escaneo de Red Inteligente:** Identificación de hosts activos y puertos abiertos usando concurrencia.
*   **🛡️ Agente de Análisis de Seguridad:** Decide el nivel de riesgo de procesos y archivos basándose en una Whitelist y patrones de comportamiento.
*   **🦠 Motor de Malware YARA:** Detección de amenazas reales (Troyanos, Ransomware, Shells) mediante reglas binarias.
*   **⚡ Agente de Mitigación:** Permite cerrar procesos maliciosos, eliminar archivos o moverlos a una **Bóveda de Cuarentena**.
*   **📋 Reportes Profesionales:** Generación automática de reportes en PDF (con tablas) y JSON (para automatización).

## 🛠️ Instalación y Uso

### Opción A: Automatizada (Windows)
Ejecuta el archivo [setup_and_run.bat](setup_and_run.bat) con privilegios de Administrador. Este script:
1. Detecta si tienes **Docker** (y te ofrece usarlo).
2. Si no, crea un entorno virtual de Python.
3. Instala todas las dependencias.
4. Lanza el diagnóstico completo.

### Opción B: Docker
Si prefieres aislamiento total:
```bash
docker build -t scanner-edr .
docker run -it scanner-edr
```

### Opción C: Manual
```bash
python -m venv .venv
source .venv/bin/activate  # En Windows: .venv\Scripts\activate
pip install -r requirements.txt
python run_full_diagnostic.py
```

## 📂 Estructura del Proyecto

*   [scanner.py](scanner.py): Motor principal y agentes (Mitigación, Análisis, Reportes).
*   [run_full_diagnostic.py](run_full_diagnostic.py): Orquestador del escaneo integral.
*   [yara_rules/](yara_rules/): Directorio para añadir reglas de inteligencia externas (.yar).
*   [quarantine_vault/](quarantine_vault/): Carpeta segura donde el sistema aísla las amenazas.
*   [html_to_pdf.py](html_to_pdf.py): Conversor de chats de Instagram a PDF (CLI + biblioteca).
*   [html_to_pdf_app.py](html_to_pdf_app.py): App móvil (Kivy) para convertir chats de Instagram a PDF.

---

## 💬 Conversor de Chat de Instagram a PDF

Herramienta independiente que convierte los archivos `message_1.html` exportados desde Instagram a PDF legibles. Soporta múltiples archivos y modo móvil.

### Instalación de dependencias adicionales

```bash
pip install beautifulsoup4 kivy
```

### Uso desde la línea de comandos (CLI)

```bash
# Convertir un archivo
python html_to_pdf.py message_1.html

# Combinar varios archivos en un único PDF
python html_to_pdf.py message_1.html message_2.html --output mi_chat.pdf

# Generar un PDF separado por cada archivo
python html_to_pdf.py message_1.html message_2.html --separados

# Especificar directorio de salida
python html_to_pdf.py message_*.html --separados --dir /ruta/salida/

# Modo interactivo (sin argumentos)
python html_to_pdf.py
```

### App móvil (Kivy — Android, iOS, Windows, Linux)

```bash
python html_to_pdf_app.py
```

La app permite:
- Seleccionar uno o varios archivos HTML desde el explorador de archivos del dispositivo.
- Elegir entre combinar todo en un único PDF o generar PDFs separados.
- Ver el progreso de la conversión y la ubicación del PDF generado.

Para compilar en Android usa [Buildozer](https://buildozer.readthedocs.io).

## ⚠️ Descargo de Responsabilidad
Esta herramienta está diseñada para fines educativos y auditorías de seguridad autorizadas. El uso de esta herramienta en redes ajenas sin permiso es ilegal.

### 4. Escaneo de Archivos Maliciosos
Busca archivos con extensiones sospechosas que podrían representar una amenaza de seguridad.

## Puertos Considerados Vulnerables

El programa identifica los siguientes puertos como potencialmente vulnerables:
- 20, 21: FTP (Protocolo de Transferencia de Archivos)
- 23: Telnet
- 25: SMTP (Correo)
- 135: RPC (Llamadas a Procedimiento Remoto)
- 137-139: NetBIOS
- 445: SMB (Compartición de Archivos Windows)
- 3389: RDP (Escritorio Remoto)
- 5900: VNC (Control Remoto)

## Advertencias

⚠️ **Importante:**
- Usa esta herramienta solo en redes y sistemas que te pertenezcan
- El escaneo de redes ajenas sin autorización puede ser ilegal
- Cerrar puertos puede afectar servicios legítimos en ejecución
- Siempre haz una copia de seguridad antes de cerrar puertos

## Licencia
MIT

## Contribuciones
Las contribuciones son bienvenidas. Por favor abre un issue o pull request para sugerencias.
