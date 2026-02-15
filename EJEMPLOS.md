# Ejemplos de Uso - Escáner de Puertos y Seguridad

Este documento proporciona ejemplos de uso del escáner de puertos y seguridad de red.

## Inicio Rápido

### Ejecutar el programa
```bash
# Usuario normal
python scanner.py

# Con permisos de administrador (para cerrar puertos)
sudo python scanner.py  # Linux/Mac
```

## Ejemplos de Uso

### 1. Escanear Puertos Locales

Cuando selecciones la opción `[1]`, el programa escaneará todos los puertos abiertos en tu PC local.

**Ejemplo de salida:**
```
[*] Escaneando puertos locales...

[+] Puertos abiertos encontrados: 5

Puerto     Proceso              PID        Servicio        Estado         
--------------------------------------------------------------------------------
22         sshd                 1234       Desconocido     OK
80         nginx                5678       Desconocido     OK
443        nginx                5678       Desconocido     OK
3306       mysqld               9012       Desconocido     OK
```

### 2. Escanear Red Local

Cuando selecciones la opción `[2]`, podrás escanear dispositivos en tu red local.

**Ejemplo:**
```
Ingresa el rango de red (ej: 192.168.1.0/24): 192.168.1.0/24

[*] Escaneando red: 192.168.1.0/24
[+] Host activo: 192.168.1.1
[+] Host activo: 192.168.1.10
[+] Host activo: 192.168.1.50

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
```

### 3. Cerrar Puertos Vulnerables

La opción `[3]` te permite cerrar puertos identificados como vulnerables.

**Flujo de trabajo:**
1. El programa muestra todos los puertos vulnerables abiertos
2. Seleccionas si cerrar un puerto específico o todos
3. Confirmas cada acción
4. El programa termina el proceso asociado al puerto

**IMPORTANTE:** Esta opción requiere permisos de administrador y puede afectar servicios en ejecución.

### 4. Escanear Archivos Maliciosos

La opción `[4]` busca archivos con extensiones sospechosas.

**Ejemplo:**
```
Ingresa la ruta del directorio a escanear: /home/usuario/Downloads
¿Escanear subdirectorios? (s/n): s

[*] Escaneando directorio: /home/usuario/Downloads

[!] Archivos sospechosos encontrados: 2

[1] setup.exe
  Ruta: /home/usuario/Downloads/setup.exe
  Tamaño: 1024000 bytes
  Modificado: 2024-01-15 10:30:45
  Hash SHA256: abc123def456...

[2] script.vbs
  Ruta: /home/usuario/Downloads/malware/script.vbs
  Tamaño: 2048 bytes
  Modificado: 2024-01-16 14:20:10
  Hash SHA256: 789xyz012abc...
```

## Consejos de Seguridad

### Interpretando los Resultados

**Puertos marcados como VULNERABLE:**
- FTP (20, 21): Transmite datos sin cifrar
- Telnet (23): No cifrado, vulnerable a interceptación
- SMB (445): Puede ser explotado si no está actualizado
- RDP (3389): Objetivo común de ataques
- VNC (5900): Puede tener contraseñas débiles

**Acciones Recomendadas:**
1. **Revisa** por qué el puerto está abierto
2. **Verifica** si realmente necesitas el servicio
3. **Actualiza** el software asociado al puerto
4. **Configura** cortafuegos para limitar el acceso
5. **Cierra** el puerto si no es necesario

### Buenas Prácticas

✅ **Hacer:**
- Ejecutar escaneos regularmente
- Mantener un registro de puertos abiertos
- Cerrar servicios innecesarios
- Usar VPN para acceso remoto
- Mantener software actualizado

❌ **No hacer:**
- Escanear redes que no te pertenecen
- Cerrar puertos sin entender su función
- Ignorar advertencias de seguridad
- Usar protocolos no cifrados en redes públicas

## Casos de Uso Comunes

### Auditoría de Seguridad Doméstica
```bash
# 1. Escanea tu PC
python scanner.py → Opción 1

# 2. Escanea tu red local
python scanner.py → Opción 2 → 192.168.1.0/24

# 3. Revisa archivos descargados
python scanner.py → Opción 4 → ~/Downloads
```

### Detección de Servicios Innecesarios
```bash
# Busca puertos abiertos que no reconoces
sudo python scanner.py → Opción 1
# Cierra los que no necesitas
→ Opción 3
```

### Monitoreo de Red Corporativa Pequeña
```bash
# Escanea todos los dispositivos en la red
python scanner.py → Opción 2 → 192.168.0.0/24
# Identifica dispositivos con puertos vulnerables abiertos
```

## Solución de Problemas

### Error: "Acceso denegado"
**Solución:** Ejecuta el programa con privilegios de administrador:
```bash
sudo python scanner.py  # Linux/Mac
```

### No se detectan hosts en la red
**Posibles causas:**
- Firewall bloqueando ping
- Rango de red incorrecto
- Los hosts están apagados

### Falsos positivos en archivos maliciosos
El escáner busca extensiones sospechosas, no significa que sean malware:
- Revisa el origen del archivo
- Usa el hash SHA256 para verificar en VirusTotal
- Analiza con un antivirus dedicado

## Recursos Adicionales

- [Guía de Puertos TCP/UDP](https://en.wikipedia.org/wiki/List_of_TCP_and_UDP_port_numbers)
- [OWASP Top 10](https://owasp.org/www-project-top-ten/)
- [Centro de Seguridad Nacional](https://www.ccn-cert.cni.es/)

## Licencia y Responsabilidad

⚠️ **IMPORTANTE:** Esta herramienta es solo para uso educativo y auditorías en sistemas propios. El uso indebido puede ser ilegal.

El usuario asume toda la responsabilidad por el uso de esta herramienta.