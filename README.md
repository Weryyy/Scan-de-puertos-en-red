# Scan-de-puertos-en-red
Código para escanear los puertos de mi propio PC y los de mi red

## Descripción
Este programa es una herramienta completa de seguridad que te permite:
- 🔍 Escanear puertos abiertos en tu PC local
- 🌐 Escanear puertos en dispositivos de tu red local
- 🔒 Cerrar puertos vulnerables detectados
- 🛡️ Buscar archivos potencialmente maliciosos

## Requisitos
- Python 3.6 o superior
- Dependencias listadas en `requirements.txt`

## Instalación

1. Clona este repositorio:
```bash
git clone https://github.com/Weryyy/Scan-de-puertos-en-red.git
cd Scan-de-puertos-en-red
```

2. Instala las dependencias:
```bash
pip install -r requirements.txt
```

## Uso

Ejecuta el programa con:
```bash
python scanner.py
```

### Para sistemas Linux/Mac (con permisos para cerrar puertos):
```bash
sudo python scanner.py
```

## Funcionalidades

### 1. Escaneo de Puertos Locales
Escanea todos los puertos abiertos en tu computadora y detecta cuáles podrían ser vulnerables.

### 2. Escaneo de Red
Escanea dispositivos en tu red local para detectar puertos abiertos. Útil para auditorías de seguridad de tu red doméstica.

### 3. Cierre de Puertos Vulnerables
Permite cerrar puertos identificados como vulnerables mediante la terminación del proceso asociado.

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
