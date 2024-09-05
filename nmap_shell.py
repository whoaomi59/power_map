import socket
import nmap
import requests
from vulners import VulnersApi


baner = """
██████╗  ██████╗ ██╗    ██╗███████╗██████╗     ███╗   ███╗ █████╗ ██████╗ 
██╔══██╗██╔═══██╗██║    ██║██╔════╝██╔══██╗    ████╗ ████║██╔══██╗██╔══██╗
██████╔╝██║   ██║██║ █╗ ██║█████╗  ██████╔╝    ██╔████╔██║███████║██████╔╝
██╔═══╝ ██║   ██║██║███╗██║██╔══╝  ██╔══██╗    ██║╚██╔╝██║██╔══██║██╔═══╝ 
██║     ╚██████╔╝╚███╔███╔╝███████╗██║  ██║    ██║ ╚═╝ ██║██║  ██║██║     
╚═╝      ╚═════╝  ╚══╝╚══╝ ╚══════╝╚═╝  ╚═╝    ╚═╝     ╚═╝╚═╝  ╚═╝╚═╝     
                                (whoaomi:))
"""


# Escaneo de puertos
def scan_ports(ip):
    nm = nmap.PortScanner()
    nm.scan(ip, '1-1024')
    open_ports = {}
    
    for host in nm.all_hosts():
        print(f"Host: {host} ({nm[host].hostname()})")
        print(f"Estado: {nm[host].state()}")
        for proto in nm[host].all_protocols():
            print(f"Protocolo: {proto}")
            ports = nm[host][proto].keys()
            for port in ports:
                service = nm[host][proto][port]['name']
                version = nm[host][proto][port].get('version', 'Unknown')
                print(f"Puerto: {port}\tServicio: {service}\tVersión: {version}")
                open_ports[port] = (service, version)
    
    return open_ports

# Imprimir información sobre la vulnerabilidad
def print_vulnerability_info(vuln):
    title = vuln.get('title', 'No title available')
    cve_id = vuln.get('id', 'No CVE ID available')
    description = vuln.get('description', 'No description available')
    url = vuln.get('url', 'No URL available')
    cvss_score = vuln.get('cvss', {}).get('score', 'No CVSS score available')

    print(f"- {title} (CVE: {cve_id}) - Severidad: {cvss_score}")
    print(f"Descripción: {description}")
    print(f"URL: {url}\n")

# Búsqueda de vulnerabilidades
def search_vulnerabilities(service_name, version):
    api_key = '408CIFQVYP45Y5KXRXMFN7WZB1RIGH3LHWIV6R3AQ2WEB7TEYHKHC4XU19B0BRP5'  # Sustituye con tu API key válida
    vulners_api = VulnersApi(api_key=api_key)
    query = f"{service_name} {version}"
    
    try:
        # Usar find_all en lugar de search
        result = vulners_api.find_all(query)
        
        if result:
            print(f"Vulnerabilidades encontradas para {service_name} versión {version}:")
            for vuln in result:
                print_vulnerability_info(vuln)
        else:
            print(f"No se encontraron vulnerabilidades para {service_name} versión {version}.")
    
    except requests.exceptions.HTTPError as http_err:
        print(f"Error HTTP: {http_err}")
    except requests.exceptions.RequestException as req_err:
        print(f"Error de solicitud: {req_err}")
    except Exception as e:
        print(f"Error al buscar vulnerabilidades: {e}")

# Herramienta principal
if __name__ == "__main__":
    print(baner)
    target_ip = input("Ingresa la IP objetivo: ")
    open_ports = scan_ports(target_ip)

    for port, (service, version) in open_ports.items():
        print(f"Buscando vulnerabilidades para {service} versión {version} en el puerto {port}...")
        search_vulnerabilities(service, version)
