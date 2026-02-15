# Guía de Inicio Rápido

## Instalación Rápida

```bash
# 1. Clonar el repositorio
git clone https://github.com/Weryyy/Scan-de-puertos-en-red.git
cd Scan-de-puertos-en-red

# 2. Instalar dependencias
pip install -r requirements.txt

# 3. Ejecutar el programa
python scanner.py
```

## Primer Uso

### Opción 1: Escanear tu PC
```
Selecciona una opción: 1
```
Verás una lista de todos los puertos abiertos en tu computadora.

### Opción 2: Escanear tu Red
```
Selecciona una opción: 2
Ingresa el rango de red: 192.168.1.0/24
```
Escanea todos los dispositivos en tu red local.

### Opción 3: Cerrar Puertos Vulnerables
```
Selecciona una opción: 3
```
⚠️ **Requiere permisos de administrador**: `sudo python scanner.py`

### Opción 4: Buscar Archivos Sospechosos
```
Selecciona una opción: 4
Ingresa la ruta: /home/usuario/Downloads
¿Escanear subdirectorios? (s/n): s
```

## Comandos Útiles

### Ejecutar con permisos de administrador (Linux/Mac)
```bash
sudo python scanner.py
```

### Ejecutar con permisos de administrador (Windows)
```powershell
# Abrir PowerShell como Administrador
python scanner.py
```

### Ver ayuda sobre comandos
```bash
python test_scanner.py  # Ejecutar pruebas
```

## Interpretación de Resultados

### Estados de Puertos
- **OK** (Verde): Puerto abierto pero no considerado vulnerable
- **VULNERABLE** (Rojo): Puerto que podría representar un riesgo de seguridad

### Puertos Comúnmente Vulnerables
| Puerto | Servicio | Riesgo |
|--------|----------|--------|
| 21 | FTP | Alto - Sin cifrado |
| 23 | Telnet | Alto - Sin cifrado |
| 445 | SMB | Medio - Vulnerable a exploits |
| 3389 | RDP | Medio - Objetivo de ataques |
| 5900 | VNC | Medio - Contraseñas débiles |

## Solución de Problemas Comunes

### Error: "ModuleNotFoundError"
```bash
pip install -r requirements.txt
```

### Error: "Permission denied"
```bash
sudo python scanner.py  # Linux/Mac
```

### No se encuentra mi red
Asegúrate de usar el formato correcto:
- Red doméstica típica: `192.168.1.0/24`
- Red empresarial: `10.0.0.0/24`

## Seguridad y Legalidad

✅ **Permitido:**
- Escanear tu propia computadora
- Escanear tu propia red doméstica
- Aprender sobre seguridad de redes

❌ **No permitido:**
- Escanear redes de otras personas sin permiso
- Usar para actividades maliciosas
- Cerrar puertos en sistemas que no te pertenecen

## Recursos Adicionales

- 📖 Ver `EJEMPLOS.md` para casos de uso detallados
- 📖 Ver `README.md` para documentación completa
- 🧪 Ejecutar `test_scanner.py` para verificar la instalación

## Preguntas Frecuentes

**P: ¿Es seguro usar esta herramienta?**
R: Sí, cuando se usa en tus propios sistemas. No la uses en redes ajenas.

**P: ¿Necesito ser experto en seguridad?**
R: No, la herramienta está diseñada para ser fácil de usar.

**P: ¿Puede dañar mi computadora?**
R: No si usas con cuidado. Siempre confirma antes de cerrar puertos.

**P: ¿Detecta todo tipo de malware?**
R: No, solo identifica archivos con extensiones sospechosas. Usa un antivirus completo para protección total.

---

**¿Necesitas más ayuda?** Consulta la documentación completa o abre un issue en GitHub.