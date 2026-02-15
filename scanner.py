#!/usr/bin/env python3
"""
Escáner de Puertos y Seguridad de Red
Este programa permite escanear puertos abiertos en tu PC y en tu red local,
detectar vulnerabilidades y buscar archivos potencialmente maliciosos.
"""

import socket
import sys
import os
import subprocess
import platform
from datetime import datetime
import ipaddress
from typing import List, Tuple
import hashlib
import concurrent.futures
import ctypes
import json
from fpdf import FPDF

try:
    import psutil
    from colorama import init, Fore, Style
    init(autoreset=True)
except ImportError:
    print("Error: Faltan dependencias necesarias.")
    print("Por favor ejecuta: pip install -r requirements.txt")
    sys.exit(1)


class PortScanner:
    """Clase para escanear puertos en hosts locales o remotos"""
    
    # Puertos comunes considerados potencialmente vulnerables
    VULNERABLE_PORTS = {
        20: "FTP Data",
        21: "FTP",
        23: "Telnet",
        25: "SMTP",
        135: "RPC",
        137: "NetBIOS",
        138: "NetBIOS",
        139: "NetBIOS",
        445: "SMB",
        3389: "RDP",
        5900: "VNC",
    }
    
    # Puertos comunes para escaneo general
    COMMON_PORTS = [20, 21, 22, 23, 25, 53, 80, 110, 143, 443, 445, 
                    3306, 3389, 5432, 5900, 8080, 8443]
    
    # Timeout para conexiones de socket (en segundos)
    DEFAULT_TIMEOUT = 1
    
    def __init__(self):
        self.timeout = self.DEFAULT_TIMEOUT
        
    def scan_port(self, host: str, port: int) -> bool:
        """Escanea un puerto específico en un host"""
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(self.timeout)
            result = sock.connect_ex((host, port))
            sock.close()
            return result == 0
        except socket.error:
            return False
    
    def scan_local_ports(self, port_range: Tuple[int, int] = None) -> List[dict]:
        """Escanea puertos abiertos en el sistema local"""
        print(f"\n{Fore.CYAN}[*] Escaneando puertos locales...{Style.RESET_ALL}")
        open_ports = []
        
        # Obtener conexiones activas usando psutil
        connections = psutil.net_connections(kind='inet')
        
        for conn in connections:
            if conn.status == 'LISTEN' and conn.laddr:
                port = conn.laddr.port
                if port_range is None or (port_range[0] <= port <= port_range[1]):
                    process_name = "Desconocido"
                    try:
                        if conn.pid:
                            process = psutil.Process(conn.pid)
                            process_name = process.name()
                    except (psutil.NoSuchProcess, psutil.AccessDenied):
                        pass
                    
                    is_vulnerable = port in self.VULNERABLE_PORTS
                    port_info = {
                        'port': port,
                        'process': process_name,
                        'pid': conn.pid,
                        'vulnerable': is_vulnerable,
                        'service': self.VULNERABLE_PORTS.get(port, "Desconocido")
                    }
                    open_ports.append(port_info)
        
        # Ordenar por número de puerto
        open_ports.sort(key=lambda x: x['port'])
        
        return open_ports
    
    def scan_network_host(self, host: str, ports: List[int] = None) -> List[dict]:
        """Escanea puertos en un host específico de la red"""
        if ports is None:
            ports = self.COMMON_PORTS
        
        open_ports = []
        
        for port in ports:
            if self.scan_port(host, port):
                is_vulnerable = port in self.VULNERABLE_PORTS
                port_info = {
                    'host': host,
                    'port': port,
                    'vulnerable': is_vulnerable,
                    'service': self.VULNERABLE_PORTS.get(port, "Desconocido")
                }
                open_ports.append(port_info)
        
        return open_ports
    
    def scan_network_range(self, network: str, ports: List[int] = None) -> dict:
        """Escanea múltiples hosts en un rango de red de forma concurrente"""
        print(f"\n{Fore.CYAN}[*] Escaneando red: {network} (Esto puede tardar...){Style.RESET_ALL}")
        
        try:
            network_obj = ipaddress.ip_network(network, strict=False)
        except ValueError as e:
            print(f"{Fore.RED}[!] Red inválida: {e}{Style.RESET_ALL}")
            return {}
        
        results = {}
        hosts = list(network_obj.hosts())
        
        print(f"{Fore.BLUE}[*] Analizando {len(hosts)} posibles hosts...{Style.RESET_ALL}")

        def process_host(ip):
            ip_str = str(ip)
            if self.is_host_alive(ip_str):
                open_ports = self.scan_network_host(ip_str, ports)
                if open_ports:
                    return ip_str, open_ports
            return None

        # Usar ThreadPoolExecutor para escaneo paralelo
        with concurrent.futures.ThreadPoolExecutor(max_workers=50) as executor:
            future_to_ip = {executor.submit(process_host, ip): ip for ip in hosts}
            for future in concurrent.futures.as_completed(future_to_ip):
                result = future.result()
                if result:
                    ip_str, open_ports = result
                    print(f"{Fore.GREEN}[+] Host activo encontrado: {ip_str} ({len(open_ports)} puertos abiertos){Style.RESET_ALL}")
                    results[ip_str] = open_ports
        
        return results
    
    def is_host_alive(self, host: str) -> bool:
        """Verifica si un host está activo mediante ping"""
        param = '-n' if platform.system().lower() == 'windows' else '-c'
        # -w usa milisegundos en Windows, segundos en Unix
        timeout_value = '500' if platform.system().lower() == 'windows' else '1'
        command = ['ping', param, '1', '-w', timeout_value, host]
        
        try:
            # Reducimos el timeout del proceso para mayor velocidad
            result = subprocess.run(command, stdout=subprocess.PIPE, 
                                  stderr=subprocess.PIPE, timeout=1)
            return result.returncode == 0
        except (subprocess.TimeoutExpired, Exception):
            return False

    def is_admin(self) -> bool:
        """Verifica si el programa se está ejecutando con privilegios de administrador"""
        try:
            if platform.system().lower() == 'windows':
                return ctypes.windll.shell32.IsUserAnAdmin() != 0
            else:
                return os.getuid() == 0
        except AttributeError:
            return False


class VulnerabilityManager:
    """Clase para gestionar vulnerabilidades de puertos"""
    
    @staticmethod
    def close_port(port: int, pid: int = None) -> bool:
        """Intenta cerrar un puerto terminando el proceso asociado"""
        if pid is None:
            return False
        
        try:
            process = psutil.Process(pid)
            process_name = process.name()
            
            print(f"{Fore.YELLOW}[!] Intentando cerrar puerto {port} (PID: {pid}, Proceso: {process_name}){Style.RESET_ALL}")
            
            # Solicitar confirmación
            response = input(f"¿Deseas terminar el proceso '{process_name}'? (s/n): ")
            if response.lower() != 's':
                print(f"{Fore.CYAN}[*] Operación cancelada{Style.RESET_ALL}")
                return False
            
            process.terminate()
            process.wait(timeout=5)
            
            print(f"{Fore.GREEN}[+] Puerto {port} cerrado exitosamente{Style.RESET_ALL}")
            return True
            
        except psutil.NoSuchProcess:
            print(f"{Fore.RED}[!] El proceso ya no existe{Style.RESET_ALL}")
            return False
        except psutil.AccessDenied:
            print(f"{Fore.RED}[!] Acceso denegado. Ejecuta el programa como administrador{Style.RESET_ALL}")
            return False
        except Exception as e:
            print(f"{Fore.RED}[!] Error al cerrar puerto: {e}{Style.RESET_ALL}")
            return False


class MalwareScanner:
    """Clase para escanear archivos potencialmente maliciosos"""
    
    # Extensiones de archivos sospechosas (principalmente para Windows)
    # En sistemas Unix, también considera .sh, .py ejecutables, y binarios sin extensión
    SUSPICIOUS_EXTENSIONS = [
        '.exe', '.bat', '.cmd', '.com', '.scr', '.pif', 
        '.vbs', '.js', '.jar', '.msi', '.dll', '.ps1'
    ]
    
    # Firmas de archivos (Magic numbers)
    FILE_SIGNATURES = {
        b'MZ': 'Ejecutable Windows (PE)',
        b'\x7fELF': 'Ejecutable Linux (ELF)',
        b'PK\x03\x04': 'Archivo Comprimido/JAR',
        b'%PDF': 'Documento PDF',
    }

    # Palabras clave sospechosas en scripts
    SUSPICIOUS_KEYWORDS = [
        'eval(', 'exec(', 'base64_decode', 'os.system', 'subprocess.Popen',
        'powershell -e', 'WScript.Shell', 'net user', 'Socket.Connect'
    ]
    
    def scan_directory(self, path: str, recursive: bool = True) -> List[dict]:
        """Escanea un directorio en busca de archivos sospechosos"""
        print(f"\n{Fore.CYAN}[*] Escaneando directorio: {path}{Style.RESET_ALL}")
        
        suspicious_files = []
        
        try:
            if recursive:
                for root, dirs, files in os.walk(path):
                    for file in files:
                        file_path = os.path.join(root, file)
                        if self.is_suspicious(file_path):
                            file_info = self.get_file_info(file_path)
                            suspicious_files.append(file_info)
            else:
                for file in os.listdir(path):
                    file_path = os.path.join(path, file)
                    if os.path.isfile(file_path) and self.is_suspicious(file_path):
                        file_info = self.get_file_info(file_path)
                        suspicious_files.append(file_info)
        
        except PermissionError:
            print(f"{Fore.RED}[!] Permiso denegado para acceder a: {path}{Style.RESET_ALL}")
        except Exception as e:
            print(f"{Fore.RED}[!] Error al escanear directorio: {e}{Style.RESET_ALL}")
        
        return suspicious_files
    
    def is_suspicious(self, file_path: str) -> bool:
        """Determina si un archivo es sospechoso con múltiples criterios"""
        _, ext = os.path.splitext(file_path)
        ext = ext.lower()
        
        # Criterio 1: Extensión sospechosa
        if ext in self.SUSPICIOUS_EXTENSIONS:
            return True
            
        # Criterio 2: Verificar encabezados (Magic Numbers) para archivos sin extensión o renombrados
        try:
            with open(file_path, 'rb') as f:
                header = f.read(4)
                for sig, desc in self.FILE_SIGNATURES.items():
                    if header.startswith(sig):
                        return True
        except Exception:
            pass

        # Criterio 3: Búsqueda de strings maliciosos en archivos de texto/scripts
        if ext in ['.js', '.vbs', '.ps1', '.bat', '.py', '.txt']:
            try:
                with open(file_path, 'r', errors='ignore') as f:
                    content = f.read(10000) # Leemos solo el inicio por rendimiento
                    for keyword in self.SUSPICIOUS_KEYWORDS:
                        if keyword.lower() in content.lower():
                            return True
            except Exception:
                pass
                
        return False

    def get_file_info(self, file_path: str) -> dict:
        """Obtiene información detallada de un archivo y razón de sospecha"""
        try:
            stat_info = os.stat(file_path)
            file_hash = self.calculate_hash(file_path)
            reason = "Extensión sospechosa"
            
            # Determinar razón más específica
            _, ext = os.path.splitext(file_path)
            if ext.lower() not in self.SUSPICIOUS_EXTENSIONS:
                reason = "Contenido/Firma sospechosa"
            
            try:
                with open(file_path, 'r', errors='ignore') as f:
                    content = f.read(5000)
                    for keyword in self.SUSPICIOUS_KEYWORDS:
                        if keyword.lower() in content.lower():
                            reason = f"Keyword detectada: {keyword}"
                            break
            except Exception:
                pass

            # Manejar timestamps inválidos
            try:
                modified_time = datetime.fromtimestamp(stat_info.st_mtime).strftime('%Y-%m-%d %H:%M:%S')
            except (OSError, ValueError):
                modified_time = "Fecha inválida"
            
            return {
                'path': file_path,
                'name': os.path.basename(file_path),
                'size': stat_info.st_size,
                'modified': modified_time,
                'hash': file_hash,
                'reason': reason
            }
        except Exception as e:
            return {
                'path': file_path,
                'name': os.path.basename(file_path),
                'error': str(e)
            }
    
    def calculate_hash(self, file_path: str) -> str:
        """Calcula el hash SHA256 de un archivo"""
        try:
            sha256_hash = hashlib.sha256()
            with open(file_path, "rb") as f:
                for byte_block in iter(lambda: f.read(4096), b""):
                    sha256_hash.update(byte_block)
            return sha256_hash.hexdigest()
        except Exception:
            return "No disponible"


class ReportGenerator:
    """Clase para generar reportes en PDF y JSON"""
    
    @staticmethod
    def generate_json(data: dict, filename: str = "reporte_seguridad.json"):
        """Exporta los datos a un archivo JSON para procesamiento automatizado"""
        try:
            with open(filename, 'w', encoding='utf-8') as f:
                json.dump(data, f, indent=4, ensure_ascii=False)
            print(f"\n{Fore.GREEN}[+] Reporte JSON generado: {filename}{Style.RESET_ALL}")
            return True
        except Exception as e:
            print(f"{Fore.RED}[!] Error al generar JSON: {e}{Style.RESET_ALL}")
            return False

    @staticmethod
    def generate_pdf(data: dict, filename: str = "reporte_seguridad.pdf"):
        """Genera un reporte visual en PDF"""
        try:
            pdf = FPDF()
            pdf.add_page()
            
            # Título
            pdf.set_font("Arial", 'B', 16)
            pdf.cell(190, 10, "Reporte de Seguridad de Red", ln=True, align='C')
            pdf.set_font("Arial", size=10)
            pdf.cell(190, 10, f"Generado el: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}", ln=True, align='C')
            pdf.ln(10)
            
            # Resumen
            pdf.set_font("Arial", 'B', 12)
            pdf.cell(190, 10, "Resumen del Escaneo", ln=True)
            pdf.set_font("Arial", size=10)
            
            for section, results in data.items():
                pdf.set_font("Arial", 'B', 11)
                pdf.cell(190, 10, f"Sección: {section.capitalize()}", ln=True)
                pdf.set_font("Arial", size=10)
                
                if isinstance(results, list):
                    for item in results:
                        pdf.multi_cell(0, 5, str(item))
                        pdf.ln(2)
                elif isinstance(results, dict):
                    for key, val in results.items():
                        pdf.multi_cell(0, 5, f"{key}: {val}")
                        pdf.ln(2)
                pdf.ln(5)

            pdf.output(filename)
            print(f"{Fore.GREEN}[+] Reporte PDF generado: {filename}{Style.RESET_ALL}")
            return True
        except Exception as e:
            print(f"{Fore.RED}[!] Error al generar PDF: {e}{Style.RESET_ALL}")
            return False


def print_banner():
    """Muestra el banner del programa"""
    banner = f"""
{Fore.CYAN}╔═══════════════════════════════════════════════════════════╗
║                                                           ║
║          ESCÁNER DE PUERTOS Y SEGURIDAD DE RED           ║
║                                                           ║
╚═══════════════════════════════════════════════════════════╝{Style.RESET_ALL}
"""
    print(banner)


def print_menu():
    """Muestra el menú principal"""
    menu = f"""
{Fore.GREEN}[1]{Style.RESET_ALL} Escanear puertos locales (Mi PC)
{Fore.GREEN}[2]{Style.RESET_ALL} Escanear puertos en la red local
{Fore.GREEN}[3]{Style.RESET_ALL} Cerrar puertos vulnerables
{Fore.GREEN}[4]{Style.RESET_ALL} Escanear archivos maliciosos
{Fore.GREEN}[5]{Style.RESET_ALL} Salir

{Fore.YELLOW}Selecciona una opción:{Style.RESET_ALL} """
    return input(menu)


def scan_local_ports_menu():
    """Menú para escanear puertos locales"""
    scanner = PortScanner()
    open_ports = scanner.scan_local_ports()
    
    if not open_ports:
        print(f"\n{Fore.GREEN}[+] No se encontraron puertos abiertos{Style.RESET_ALL}")
        return
    
    print(f"\n{Fore.GREEN}[+] Puertos abiertos encontrados: {len(open_ports)}{Style.RESET_ALL}\n")
    print(f"{'Puerto':<10} {'Proceso':<20} {'PID':<10} {'Servicio':<15} {'Estado':<15}")
    print("-" * 80)
    
    for port_info in open_ports:
        status = f"{Fore.RED}VULNERABLE{Style.RESET_ALL}" if port_info['vulnerable'] else f"{Fore.GREEN}OK{Style.RESET_ALL}"
        print(f"{port_info['port']:<10} {port_info['process']:<20} {str(port_info['pid']):<10} "
              f"{port_info['service']:<15} {status}")
    
    vulnerable_count = sum(1 for p in open_ports if p['vulnerable'])
    if vulnerable_count > 0:
        print(f"\n{Fore.RED}[!] Se encontraron {vulnerable_count} puertos potencialmente vulnerables{Style.RESET_ALL}")
    
    # Opción de exportar
    export = input(f"\n¿Deseas exportar estos resultados? (s/n): ").lower()
    if export == 's':
        data = {"puertos_locales": open_ports}
        ReportGenerator.generate_json(data, "puertos_locales.json")
        ReportGenerator.generate_pdf(data, "puertos_locales.pdf")


def scan_network_menu():
    """Menú para escanear puertos en la red"""
    scanner = PortScanner()
    
    print(f"\n{Fore.CYAN}=== ESCANEO DE RED ==={Style.RESET_ALL}")
    network = input("Ingresa el rango de red (ej: 192.168.1.0/24): ")
    
    results = scanner.scan_network_range(network)
    
    if not results:
        print(f"\n{Fore.YELLOW}[*] No se encontraron hosts activos o puertos abiertos{Style.RESET_ALL}")
        return
    
    print(f"\n{Fore.GREEN}[+] Resultados del escaneo:{Style.RESET_ALL}\n")
    
    for host, ports in results.items():
        print(f"\n{Fore.CYAN}Host: {host}{Style.RESET_ALL}")
        print(f"{'Puerto':<10} {'Servicio':<15} {'Estado':<15}")
        print("-" * 40)
        
        for port_info in ports:
            status = f"{Fore.RED}VULNERABLE{Style.RESET_ALL}" if port_info['vulnerable'] else f"{Fore.GREEN}OK{Style.RESET_ALL}"
            print(f"{port_info['port']:<10} {port_info['service']:<15} {status}")
    
    # Opción de exportar
    export = input(f"\n¿Deseas exportar estos resultados? (s/n): ").lower()
    if export == 's':
        ReportGenerator.generate_json(results, "escaneo_red.json")
        ReportGenerator.generate_pdf({"red_local": results}, "escaneo_red.pdf")


def close_vulnerable_ports_menu():
    """Menú para cerrar puertos vulnerables"""
    scanner = PortScanner()
    manager = VulnerabilityManager()
    
    open_ports = scanner.scan_local_ports()
    vulnerable_ports = [p for p in open_ports if p['vulnerable']]
    
    if not vulnerable_ports:
        print(f"\n{Fore.GREEN}[+] No se encontraron puertos vulnerables abiertos{Style.RESET_ALL}")
        return
    
    print(f"\n{Fore.RED}[!] Puertos vulnerables encontrados:{Style.RESET_ALL}\n")
    print(f"{'#':<5} {'Puerto':<10} {'Proceso':<20} {'PID':<10} {'Servicio':<15}")
    print("-" * 65)
    
    for idx, port_info in enumerate(vulnerable_ports, 1):
        print(f"{idx:<5} {port_info['port']:<10} {port_info['process']:<20} "
              f"{str(port_info['pid']):<10} {port_info['service']:<15}")
    
    print(f"\n{Fore.YELLOW}Opciones:{Style.RESET_ALL}")
    print("[1] Cerrar un puerto específico")
    print("[2] Cerrar todos los puertos vulnerables")
    print("[3] Volver al menú principal")
    
    choice = input("\nSelecciona una opción: ")
    
    if choice == '1':
        try:
            port_num = int(input("Ingresa el número del puerto a cerrar: "))
            port_info = next((p for p in vulnerable_ports if p['port'] == port_num), None)
            if port_info:
                manager.close_port(port_info['port'], port_info['pid'])
            else:
                print(f"{Fore.RED}[!] Puerto no encontrado{Style.RESET_ALL}")
        except ValueError:
            print(f"{Fore.RED}[!] Entrada inválida{Style.RESET_ALL}")
    
    elif choice == '2':
        print(f"\n{Fore.RED}[!] ADVERTENCIA: Esto intentará cerrar {len(vulnerable_ports)} puerto(s) vulnerable(s){Style.RESET_ALL}")
        confirm = input("¿Estás seguro de que deseas continuar? (s/n): ")
        if confirm.lower() == 's':
            print(f"\n{Fore.YELLOW}[!] Cerrando todos los puertos vulnerables...{Style.RESET_ALL}")
            for port_info in vulnerable_ports:
                manager.close_port(port_info['port'], port_info['pid'])
        else:
            print(f"{Fore.CYAN}[*] Operación cancelada{Style.RESET_ALL}")


def scan_malware_menu():
    """Menú para escanear archivos maliciosos"""
    scanner = MalwareScanner()
    
    print(f"\n{Fore.CYAN}=== ESCANEO DE ARCHIVOS MALICIOSOS ==={Style.RESET_ALL}")
    path = input("Ingresa la ruta del directorio a escanear: ")
    
    if not os.path.exists(path):
        print(f"{Fore.RED}[!] La ruta no existe{Style.RESET_ALL}")
        return
    
    if not os.path.isdir(path):
        print(f"{Fore.RED}[!] La ruta debe ser un directorio{Style.RESET_ALL}")
        return
    
    recursive = input("¿Escanear subdirectorios? (s/n): ").lower() == 's'
    
    suspicious_files = scanner.scan_directory(path, recursive)
    
    if not suspicious_files:
        print(f"\n{Fore.GREEN}[+] No se encontraron archivos sospechosos{Style.RESET_ALL}")
        return
    
    print(f"\n{Fore.YELLOW}[!] Archivos sospechosos encontrados: {len(suspicious_files)}{Style.RESET_ALL}\n")
    
    for idx, file_info in enumerate(suspicious_files, 1):
        print(f"\n{Fore.RED}[{idx}] {file_info['name']}{Style.RESET_ALL}")
        print(f"  Ruta: {file_info['path']}")
        if 'error' not in file_info:
            print(f"  Razón: {Fore.YELLOW}{file_info.get('reason', 'Desconocida')}{Style.RESET_ALL}")
            print(f"  Tamaño: {file_info['size']} bytes")
            print(f"  Modificado: {file_info['modified']}")
            print(f"  Hash SHA256: {file_info['hash']}")
        else:
            print(f"  Error: {file_info['error']}")
    
    # Opción de exportar
    export = input(f"\n¿Deseas exportar estos resultados? (s/n): ").lower()
    if export == 's':
        data = {"archivos_sospechosos": suspicious_files}
        ReportGenerator.generate_json(data, "malware_detectado.json")
        ReportGenerator.generate_pdf(data, "malware_detectado.pdf")


def main():
    """Función principal"""
    print_banner()
    
    scanner_instance = PortScanner()
    is_admin = scanner_instance.is_admin()
    
    # Mostrar estado de privilegios
    if is_admin:
        print(f"{Fore.GREEN}[+] Ejecutando con permisos de ADMINISTRADOR. Funciones completas activas.{Style.RESET_ALL}")
    else:
        print(f"{Fore.YELLOW}[!] Ejecutando con permisos de usuario estándar.{Style.RESET_ALL}")
        if platform.system() == "Windows":
            print(f"{Fore.YELLOW}[!] Para poder cerrar puertos y procesos del sistema, ejecuta como Administrador.{Style.RESET_ALL}")
        else:
            print(f"{Fore.YELLOW}[!] Para poder cerrar puertos, ejecuta con sudo.{Style.RESET_ALL}")
    
    while True:
        try:
            choice = print_menu()
            
            if choice == '1':
                scan_local_ports_menu()
            elif choice == '2':
                scan_network_menu()
            elif choice == '3':
                close_vulnerable_ports_menu()
            elif choice == '4':
                scan_malware_menu()
            elif choice == '5':
                print(f"\n{Fore.GREEN}[+] ¡Hasta luego!{Style.RESET_ALL}")
                break
            else:
                print(f"\n{Fore.RED}[!] Opción inválida{Style.RESET_ALL}")
            
            input(f"\n{Fore.CYAN}Presiona Enter para continuar...{Style.RESET_ALL}")
            
        except KeyboardInterrupt:
            print(f"\n\n{Fore.YELLOW}[!] Operación cancelada por el usuario{Style.RESET_ALL}")
            break
        except Exception as e:
            print(f"\n{Fore.RED}[!] Error inesperado: {e}{Style.RESET_ALL}")


if __name__ == "__main__":
    main()
