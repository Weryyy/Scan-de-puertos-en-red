# Demostración del Escáner de Puertos y Seguridad

Este documento muestra ejemplos visuales de cómo funciona cada característica del escáner.

## 📋 Índice
1. [Menú Principal](#menú-principal)
2. [Escaneo de Puertos Locales](#escaneo-de-puertos-locales)
3. [Escaneo de Red](#escaneo-de-red)
4. [Gestión de Puertos Vulnerables](#gestión-de-puertos-vulnerables)
5. [Escaneo de Archivos Maliciosos](#escaneo-de-archivos-maliciosos)

---

## Menú Principal

Al ejecutar `python scanner.py`, verás:

```
╔═══════════════════════════════════════════════════════════╗
║                                                           ║
║          ESCÁNER DE PUERTOS Y SEGURIDAD DE RED           ║
║                                                           ║
╚═══════════════════════════════════════════════════════════╝

[1] Escanear puertos locales (Mi PC)
[2] Escanear puertos en la red local
[3] Cerrar puertos vulnerables
[4] Escanear archivos maliciosos
[5] Salir

Selecciona una opción:
```

---

## Escaneo de Puertos Locales

**Opción 1** - Muestra todos los puertos abiertos en tu computadora:

```
[*] Escaneando puertos locales...

[+] Puertos abiertos encontrados: 8

Puerto     Proceso              PID        Servicio        Estado         
--------------------------------------------------------------------------------
22         sshd                 1234       Desconocido     OK
80         nginx                5678       Desconocido     OK
443        nginx                5678       Desconocido     OK
445        smbd                 9012       SMB             VULNERABLE
3306       mysqld               3456       Desconocido     OK
3389       xrdp                 7890       RDP             VULNERABLE
5900       vncserver            2345       VNC             VULNERABLE
8080       node                 6789       Desconocido     OK

[!] Se encontraron 3 puertos potencialmente vulnerables
```

### Interpretación:
- ✅ **Verde (OK)**: Puertos normales sin riesgos conocidos
- ⚠️ **Rojo (VULNERABLE)**: Puertos que podrían ser explotados
- Muestra el proceso, PID y servicio asociado a cada puerto

---

## Escaneo de Red

**Opción 2** - Escanea dispositivos en tu red local:

```
=== ESCANEO DE RED ===
Ingresa el rango de red (ej: 192.168.1.0/24): 192.168.1.0/24

[*] Escaneando red: 192.168.1.0/24
[+] Host activo: 192.168.1.1
[+] Host activo: 192.168.1.10
[+] Host activo: 192.168.1.50
[+] Host activo: 192.168.1.100

[+] Resultados del escaneo:

Host: 192.168.1.1
Puerto     Servicio        Estado         
----------------------------------------
80         Desconocido     OK
443        Desconocido     OK

Host: 192.168.1.50
Puerto     Servicio        Estado         
----------------------------------------
22         Desconocido     OK
445        SMB             VULNERABLE
3389       RDP             VULNERABLE

Host: 192.168.1.100
Puerto     Servicio        Estado         
----------------------------------------
21         FTP             VULNERABLE
22         Desconocido     OK
80         Desconocido     OK
```

### Casos de Uso:
- 🏠 Auditar seguridad de tu red doméstica
- 🔍 Descubrir dispositivos desconocidos
- 🛡️ Identificar servicios vulnerables en tu red

---

## Gestión de Puertos Vulnerables

**Opción 3** - Cierra puertos que representan riesgos:

```
[!] Puertos vulnerables encontrados:

#      Puerto     Proceso              PID        Servicio       
-----------------------------------------------------------------
1      445        smbd                 9012       SMB            
2      3389       xrdp                 7890       RDP            
3      5900       vncserver            2345       VNC            

Opciones:
[1] Cerrar un puerto específico
[2] Cerrar todos los puertos vulnerables
[3] Volver al menú principal

Selecciona una opción: 1
Ingresa el número del puerto a cerrar: 445

[!] Intentando cerrar puerto 445 (PID: 9012, Proceso: smbd)
¿Deseas terminar el proceso 'smbd'? (s/n): s
[+] Puerto 445 cerrado exitosamente
```

### ⚠️ Advertencias:
- Requiere permisos de administrador (`sudo`)
- Cerrar puertos puede afectar servicios legítimos
- Siempre confirma antes de proceder

---

## Escaneo de Archivos Maliciosos

**Opción 4** - Busca archivos con extensiones sospechosas:

```
=== ESCANEO DE ARCHIVOS MALICIOSOS ===
Ingresa la ruta del directorio a escanear: /home/usuario/Downloads
¿Escanear subdirectorios? (s/n): s

[*] Escaneando directorio: /home/usuario/Downloads

[!] Archivos sospechosos encontrados: 3

[1] setup.exe
  Ruta: /home/usuario/Downloads/setup.exe
  Tamaño: 2048000 bytes
  Modificado: 2024-01-15 10:30:45
  Hash SHA256: abc123def456789012345678901234567890123456789012345678901234

[2] script.vbs
  Ruta: /home/usuario/Downloads/scripts/script.vbs
  Tamaño: 1024 bytes
  Modificado: 2024-01-16 14:20:10
  Hash SHA256: 789xyz012abc345def678901234567890123456789012345678901234

[3] install.bat
  Ruta: /home/usuario/Downloads/tools/install.bat
  Tamaño: 512 bytes
  Modificado: 2024-01-17 09:15:30
  Hash SHA256: 456def789abc012345678901234567890123456789012345678901234
```

### Extensiones Detectadas:
- `.exe`, `.bat`, `.cmd` - Ejecutables Windows
- `.vbs`, `.js` - Scripts
- `.jar`, `.msi`, `.dll` - Instaladores/Librerías
- `.scr`, `.pif`, `.com` - Otros ejecutables

### Qué Hacer con Archivos Sospechosos:
1. ✅ Verificar el origen del archivo
2. 🔍 Buscar el hash SHA256 en [VirusTotal](https://www.virustotal.com)
3. 🛡️ Analizar con antivirus
4. 🗑️ Eliminar si es malicioso

---

## Características Especiales

### 🎨 Interfaz con Colores
- **Cyan**: Información y mensajes del sistema
- **Verde**: Operaciones exitosas
- **Amarillo**: Advertencias
- **Rojo**: Peligros y vulnerabilidades

### 🔒 Seguridad Integrada
- Confirmación antes de acciones destructivas
- Verificación de permisos
- Manejo seguro de errores
- Sin almacenamiento de datos sensibles

### 📊 Información Detallada
- Nombres de procesos
- IDs de proceso (PID)
- Hashes SHA256 de archivos
- Timestamps de modificación

---

## Ejemplos de Flujos de Trabajo

### Auditoría de Seguridad Completa

```bash
# 1. Escanear puertos locales
python scanner.py
→ Opción 1

# 2. Identificar vulnerabilidades
→ Revisar puertos marcados como VULNERABLE

# 3. Escanear red local
→ Opción 2
→ Ingresar: 192.168.1.0/24

# 4. Cerrar puertos vulnerables
→ Opción 3
→ Seleccionar puertos a cerrar

# 5. Escanear descargas
→ Opción 4
→ Ruta: ~/Downloads
```

### Monitoreo Regular

```bash
# Ejecutar semanalmente para detectar cambios
python scanner.py
→ Opción 1 (Puertos locales)
→ Comparar con escaneos anteriores
→ Investigar puertos nuevos
```

### Respuesta a Incidentes

```bash
# Si sospechas de infección
1. Escanear archivos (Opción 4)
2. Verificar puertos abiertos (Opción 1)
3. Cerrar puertos sospechosos (Opción 3)
4. Escanear red (Opción 2) para verificar propagación
```

---

## Comparación con Otras Herramientas

| Característica | Este Escáner | nmap | Wireshark |
|----------------|--------------|------|-----------|
| Fácil de usar | ✅ | ❌ | ❌ |
| Interfaz gráfica | ❌ | ❌ | ✅ |
| Cierre de puertos | ✅ | ❌ | ❌ |
| Escaneo de malware | ✅ | ❌ | ❌ |
| Escaneo de red | ✅ | ✅ | ✅ |
| Análisis profundo | ❌ | ✅ | ✅ |
| Requerimientos | Python | C | C++ |

---

## Mejores Prácticas

### ✅ Hacer
- Ejecutar escaneos regulares
- Documentar puertos abiertos
- Investigar puertos desconocidos
- Mantener software actualizado
- Usar en tu propia red

### ❌ No Hacer
- Escanear redes ajenas
- Cerrar puertos sin investigar
- Ignorar advertencias
- Compartir resultados públicamente
- Usar para acceso no autorizado

---

## Solución de Problemas

### El escáner no encuentra hosts
**Solución:**
- Verificar rango de red correcto
- Comprobar firewall local
- Usar formato correcto (ej: 192.168.1.0/24)

### "Permission denied" al cerrar puertos
**Solución:**
```bash
sudo python scanner.py  # Linux/Mac
```

### Falsos positivos en archivos
**Solución:**
- Los archivos .exe legítimos se marcarán como sospechosos
- Verificar origen y hash del archivo
- Usar contexto para determinar si es malicioso

---

## Recursos Adicionales

📚 **Documentación:**
- `README.md` - Documentación completa
- `EJEMPLOS.md` - Ejemplos detallados
- `QUICKSTART.md` - Inicio rápido

🧪 **Pruebas:**
```bash
python test_scanner.py
```

🔗 **Enlaces Útiles:**
- [Lista de Puertos TCP/UDP](https://en.wikipedia.org/wiki/List_of_TCP_and_UDP_port_numbers)
- [OWASP Top 10](https://owasp.org/www-project-top-ten/)
- [VirusTotal](https://www.virustotal.com/)

---

## Licencia y Disclaimer

⚠️ **IMPORTANTE:** Esta herramienta es para uso educativo y auditorías autorizadas únicamente.

El uso indebido puede ser ilegal. El usuario asume toda la responsabilidad.

MIT License - Ver archivo LICENSE para más detalles.
