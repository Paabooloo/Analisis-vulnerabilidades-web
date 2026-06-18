import pandas as pd
import requests
import time
import re
import io
from tabulate import tabulate 
import urllib3


urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

def cves(vulnerabilidad_detectada, archivo):
    print("\n[+] Cargando módulo de verificación de CVEs...")
    df = pd.read_csv(io.StringIO(archivo))
    
    # Extraemos las columnas asegurando que se lean como texto limpio
    urls_o_ips = df['IP Address'].astype(str).str.strip()
    cves_objetivo = df['Vulnerability'].astype(str).str.strip().str.upper()
    total_registros = len(urls_o_ips)
    
    # Estructura de resultados solicitada
    df_resultados = pd.DataFrame({
        'IP afectada': urls_o_ips,
        'CVE': cves_objetivo,
        'Estado CVE': 'Seguro 🔒', 
        'Correcto': '✅'
    })
    
    headers_peticion = {
        'User-Agent': 'ScoreCardScanner/1.0'
    }

    

    for index, ip in enumerate(urls_o_ips):

        cve_a_buscar = cves_objetivo[index]
        

        if (pd.isna(ip) or ip.strip() == '' or ip.lower() == 'nan' or 
            pd.isna(cve_a_buscar) or cve_a_buscar.strip() == '' or cve_a_buscar.lower() == 'nan'):
            
            df_resultados.at[index, 'Estado CVE'] = 'No Soportado'
            df_resultados.at[index, 'Correcto'] = '❌'
            continue
        # ------------------------------------------------------------------

        
        url_peticion = 'http://' + ip
        resultado_auditoria = 'Seguro 🔒'

        try:
    
            response = requests.get(url_peticion, headers=headers_peticion, timeout=1.5, verify=False)
            
            server_header = response.headers.get('Server', '').lower()
            x_powered = response.headers.get('X-Powered-By', '').lower()
            banner_servidor = f"{server_header} {x_powered}".strip()

            if not banner_servidor:
                df_resultados.at[index, 'Estado CVE'] = 'Seguro 🔒'
                continue

            # 2. Consultar la API del NVD para mapear el CVE de la fila
            url_api_nvd = f"https://services.nvd.nist.gov/rest/json/cves/2.0?cveId={cve_a_buscar}"
            api_response = requests.get(url_api_nvd, headers=headers_peticion, timeout=3)
            
            # Pausa reglamentaria anti-bloqueo para la API de EE.UU.
            time.sleep(0.5)

            if api_response.status_code == 200:
                datos_cve = api_response.json()
                vulnerabilities = datos_cve.get('vulnerabilities', [])
                
                if vulnerabilities:
                    descripcion_cve = vulnerabilities[0]['cve']['descriptions'][0]['value'].lower()
                    tecnologias = ['apache', 'nginx', 'iis', 'php', 'openssl', 'tomcat', 'litespeed']
                    
                    for tech in tecnologias:
                        if tech in descripcion_cve and tech in banner_servidor:
                            versiones_ip = re.findall(r'\d+\.\d+(?:\.\d+)?', banner_servidor)
                            for ver in versiones_ip:
                                if ver in descripcion_cve:
                                    resultado_auditoria = 'No Soportado'
                                    break
                    if resultado_auditoria == 'No Soportado':
                            continue
                else:
                    resultado_auditoria = 'No Soportado'
                    
            else:
                resultado_auditoria = 'No Soportado'

        except requests.exceptions.Timeout:
            resultado_auditoria = 'No Soportado'
        except requests.exceptions.RequestException:
            resultado_auditoria = 'No Soportado'

        if resultado_auditoria == 'Seguro 🔒':
            df_resultados.at[index, 'Estado CVE'] = 'Seguro 🔒'
        else:
            df_resultados.at[index, 'Estado CVE'] = 'No Soportado'
            df_resultados.at[index, 'Correcto'] = '❌'
    

    print("                 🎯 RESULTADOS DE LA AUDITORÍA DE", vulnerabilidad_detectada,"                 \n")
    tabla_html = df_resultados.to_html(
    classes="w-full text-left border-collapse", 
    index=False, 
    border=0,
    justify="left")
    return tabla_html