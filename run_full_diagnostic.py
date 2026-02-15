
import sys
import os
from scanner import PortScanner, MalwareScanner, ReportGenerator, SecurityAgent, MitigationAgent
from colorama import Fore, Style, init

init(autoreset=True)


def run_diagnostic():
    print(f"{Fore.CYAN}=== INICIANDO DIAGNÓSTICO INTEGRAL CON AGENTE INTELIGENTE ==={Style.RESET_ALL}")

    ps = PortScanner()
    ms = MalwareScanner()
    rg = ReportGenerator()
    sa = SecurityAgent()
    ma = MitigationAgent()

    # Cargar reglas YARA avanzadas de la nueva carpeta
    external_rules = os.path.join(os.getcwd(), "yara_rules", "advanced_detection.yar")
    if os.path.exists(external_rules):
        ms.load_external_rules(external_rules)

    diagnostic_data = {}

    # 1. Escaneo de Puertos Locales + Análisis del Agente
    print(
        f"\n{Fore.YELLOW}[1/3] Escaneando y Analizando Puertos Locales...{Style.RESET_ALL}")
    local_ports = ps.scan_local_ports()
    analyzed_ports = sa.analyze_local_security(local_ports)
    diagnostic_data["puertos_locales"] = analyzed_ports
    print(f"   - {len(local_ports)} puertos analizados por el Agente.")

    # 2. Escaneo de Malware + Análisis de Confianza
    print(
        f"\n{Fore.YELLOW}[2/3] Escaneando y Evaluando Confianza de Archivos...{Style.RESET_ALL}")
    malware_results = ms.scan_directory(os.getcwd(), recursive=True)
    analyzed_malware = sa.analyze_malware_confidence(malware_results)
    diagnostic_data["malware"] = analyzed_malware
    print(f"   - {len(malware_results)} archivos evaluados.")

    # 3. Escaneo de Red Local
    print(
        f"\n{Fore.YELLOW}[3/3] Escaneando Red Local (172.20.144.0/24)...{Style.RESET_ALL}")
    network_results = ps.scan_network_range(
        "172.20.144.0/24", ports=[80, 443, 445, 3389])
    diagnostic_data["red_local"] = network_results

    # Generar Reportes Profesionales
    json_path = "DIAGNOSTICO_AGENTE.json"
    print(f"\n{Fore.CYAN}=== GENERANDO REPORTES PROFESIONALES ==={Style.RESET_ALL}")
    rg.generate_json(diagnostic_data, json_path)
    rg.generate_pdf(diagnostic_data, "DIAGNOSTICO_AGENTE.pdf")

    print(f"\n{Fore.GREEN}¡Análisis del Agente completado! Revisa DIAGNOSTICO_AGENTE.pdf para ver las tablas y recomendaciones.{Style.RESET_ALL}")

    # Nuevo: Agente de Mitigación
    apply_mitigation = input(
        f"\n{Fore.RED}¿Deseas activar el Agente de Mitigación para aplicar las acciones recomendadas? (s/n): {Style.RESET_ALL}")
    if apply_mitigation.lower() == 's':
        ma.execute_mitigation(json_path)

    # Mostrar resumen de acciones finales
    ma.print_summary()


if __name__ == "__main__":
    run_diagnostic()
