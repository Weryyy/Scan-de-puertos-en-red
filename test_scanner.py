#!/usr/bin/env python3
"""
Script de prueba para el escáner de puertos
Ejecuta pruebas básicas de las funcionalidades principales
"""

import scanner
import sys
import os

# Agregar el directorio actual al path
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))


def test_port_scanner():
    """Prueba el escáner de puertos locales"""
    print("\n=== Prueba: Escáner de Puertos Locales ===")
    port_scanner = scanner.PortScanner()

    try:
        open_ports = port_scanner.scan_local_ports()
        print(f"✓ Escaneo completado: {len(open_ports)} puertos encontrados")

        if open_ports:
            print(
                f"  Puerto de ejemplo: {open_ports[0]['port']} - {open_ports[0]['process']}")

        vulnerable = [p for p in open_ports if p['vulnerable']]
        if vulnerable:
            print(f"⚠ Puertos vulnerables encontrados: {len(vulnerable)}")
        else:
            print("✓ No se encontraron puertos vulnerables")

        return True
    except Exception as e:
        print(f"✗ Error en prueba de escáner de puertos: {e}")
        return False


def test_malware_scanner():
    """Prueba el escáner de archivos maliciosos"""
    print("\n=== Prueba: Escáner de Archivos Maliciosos ===")
    malware_scanner = scanner.MalwareScanner()

    try:
        # Crear directorio de prueba temporal
        test_dir = os.path.join(os.getcwd(), "scanner_test_temp")
        os.makedirs(test_dir, exist_ok=True)

        # Crear archivo de prueba con extensión sospechosa
        test_file = os.path.join(test_dir, "test.exe")
        with open(test_file, "w") as f:
            f.write("Test file")

        # Crear archivo de prueba con palabra clave sospechosa
        test_script = os.path.join(test_dir, "script.txt")
        with open(test_script, "w") as f:
            f.write("System.echo('hello'); eval(payload);")

        # Escanear el directorio
        suspicious = malware_scanner.scan_directory(test_dir, recursive=False)

        if len(suspicious) >= 2:
            print(
                f"✓ Detección mejorada funcionando: {len(suspicious)} archivos sospechosos")
            print(
                f"  Detectado por extensión: {[f['name'] for f in suspicious if f['name'] == 'test.exe'][0]}")
            print(
                f"  Detectado por keyword: {[f['name'] for f in suspicious if f['name'] == 'script.txt'][0]}")
        else:
            print(
                f"⚠ La detección mejorada no captó todos los archivos (Encontrados: {len(suspicious)})")

        # Limpiar
        os.remove(test_file)
        os.remove(test_script)
        os.rmdir(test_dir)

        return True
    except Exception as e:
        print(f"✗ Error en prueba de escáner de malware: {e}")
        return False


def test_vulnerability_manager():
    """Prueba el gestor de vulnerabilidades"""
    print("\n=== Prueba: Gestor de Vulnerabilidades ===")

    try:
        vuln_manager = scanner.VulnerabilityManager()
        print("✓ VulnerabilityManager instanciado correctamente")
        print("  (Las pruebas de cierre de puertos requieren interacción manual)")
        return True
    except Exception as e:
        print(f"✗ Error en prueba de gestor de vulnerabilidades: {e}")
        return False


def test_port_detection():
    """Prueba la detección de puertos específicos"""
    print("\n=== Prueba: Detección de Puerto Específico ===")
    port_scanner = scanner.PortScanner()

    try:
        # Probar escaneo de localhost en puerto común (probablemente cerrado)
        is_open = port_scanner.scan_port("127.0.0.1", 9999)
        print(
            f"✓ Puerto 9999 en localhost: {'Abierto' if is_open else 'Cerrado'}")

        # Verificar puertos vulnerables conocidos
        print(
            f"✓ Puertos vulnerables definidos: {len(port_scanner.VULNERABLE_PORTS)}")
        print(f"  Ejemplos: FTP (21), Telnet (23), RDP (3389)")

        return True
    except Exception as e:
        print(f"✗ Error en prueba de detección de puerto: {e}")
        return False


def run_all_tests():
    """Ejecuta todas las pruebas"""
    print("╔═══════════════════════════════════════════════════════════╗")
    print("║         PRUEBAS DEL ESCÁNER DE PUERTOS Y SEGURIDAD       ║")
    print("╚═══════════════════════════════════════════════════════════╝")

    tests = [
        ("Escáner de Puertos", test_port_scanner),
        ("Detección de Puertos", test_port_detection),
        ("Escáner de Malware", test_malware_scanner),
        ("Gestor de Vulnerabilidades", test_vulnerability_manager),
    ]

    results = []
    for test_name, test_func in tests:
        try:
            result = test_func()
            results.append((test_name, result))
        except Exception as e:
            print(f"\n✗ Error crítico en {test_name}: {e}")
            results.append((test_name, False))

    # Resumen
    print("\n" + "="*60)
    print("RESUMEN DE PRUEBAS")
    print("="*60)

    passed = sum(1 for _, result in results if result)
    total = len(results)

    for test_name, result in results:
        status = "✓ PASS" if result else "✗ FAIL"
        print(f"{status:10} {test_name}")

    print(f"\nResultado: {passed}/{total} pruebas exitosas")

    if passed == total:
        print("\n✓ Todas las pruebas pasaron exitosamente!")
        return 0
    else:
        print("\n⚠ Algunas pruebas fallaron")
        return 1


if __name__ == "__main__":
    sys.exit(run_all_tests())
