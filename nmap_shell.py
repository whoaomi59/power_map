import socket
import nmap
import vulners

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

# Búsqueda de vulnerabilidades
# Configurar la API correctamente usando VulnersApi
def search_vulnerabilities(service_name, version):
    vulners_api = vulners.VulnersApi(api_key='408CIFQVYP45Y5KXRXMFN7WZB1RIGH3LHWIV6R3AQ2WEB7TEYHKHC4XU19B0BRP5')  # Asegúrate de usar tu API Key válida
    query = f"{service_name} {version}"
    
    try:
        # Usar find_all en lugar de search
        result = vulners_api.find_all(query)
        
        if result:
            print(f"Vulnerabilidades encontradas para {service} versión {version}:")
            for vuln in result:
                print(f"Vulnerabilidades encontradas para {service} versión {version}:")
                print(f"Descripción: {vuln['description']}\n")
        else:
            print(f"No se encontraron vulnerabilidades para {service_name} versión {version}.")
    
    except requests.exceptions.HTTPError as http_err:
        print(f"Error HTTP: {http_err}")
    except Exception as e:
        print(f"Error al buscar vulnerabilidades: {e}")

# Herramienta principal
if __name__ == "__main__":
    target_ip = input("Ingresa la IP objetivo: ")
    open_ports = scan_ports(target_ip)

    for port, (service, version) in open_ports.items():
        print(f"Buscando vulnerabilidades para {service} versión {version} en el puerto {port}...")
        search_vulnerabilities(service, version)
