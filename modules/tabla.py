import pandas as pd
import requests
import time
import io
def tabla(archivo):
    df = pd.read_csv(io.StringIO(archivo))
    urls_o_ips = df['IP Address']
    cves_objetivo = df['Vulnerability'].astype(str).str.strip().str.upper()
    df_resultados = pd.DataFrame({
       
        'IP afectada': urls_o_ips,
        'CVE': cves_objetivo,
        'Descripción':'DEFAULT',
        'Producto': "DEFAULT",
        'Componente afectado':"DEFAULT",
        'Versiones afectadas (general)': "DEFAULT",	
        'Versión corregida / recomendada': "DEFAULT"
    })
    headers_peticion = {
        'User-Agent': 'ScoreCardScanner/1.0'
    }

    
    for index, row in df_resultados.iterrows():
        cve_id = str(row['CVE']).strip().upper()
    
    # Validamos que haya un CVE real en esa fila
        if cve_id == 'NAN' or cve_id == '' or cve_id == 'NONE':
            continue
        
           
        url = f"https://services.nvd.nist.gov/rest/json/cves/2.0?cveId={cve_id}"
        try:
            response = requests.get(url, headers=headers_peticion)

            if response.status_code == 200:
                data = response.json()

                if 'vulnerabilities' in data and len(data['vulnerabilities']) > 0:
                    cve_data = data['vulnerabilities'][0]['cve']

                    # -------------------------------------------------------------
                    # BLOQUE A: DESCRIPCIÓN Y TRADUCCIÓN
                    # -------------------------------------------------------------
                    descripciones = cve_data.get('descriptions', [])
                    desc_final = "Sin descripción disponible en la API."

                    for desc in descripciones:
                        if desc['lang'] == 'es':
                            desc_final = desc['value']
                            break # Si hay español, nos quedamos con ese y paramos de buscar
                        
                    # Guardamos en TU columna
                    df_resultados.at[index, 'Descripción'] = desc_final

                    # -------------------------------------------------------------
                    # BLOQUE B: PRODUCTO, COMPONENTE Y VERSIONES (CPE)
                    # -------------------------------------------------------------
                    encontro_cpe = False
                    if 'configurations' in cve_data:
                        for config in cve_data['configurations']:
                            for node in config.get('nodes', []):
                                for match in node.get('cpeMatch', []):

                                    cpe_str = match.get('criteria', '')
                                    partes_cpe = cpe_str.split(':')

                                    # Extraemos Producto y Componente
                                    if len(partes_cpe) > 4:
                                        componente = partes_cpe[3] 
                                        producto = partes_cpe[4] 
                                    else:
                                        componente, producto = "Desconocido", "Desconocido"

                                    # Extraemos Versiones Afectadas
                                    v_start = match.get('versionStartIncluding', 'N/A')
                                    v_end = match.get('versionEndExcluding', match.get('versionEndIncluding', 'N/A'))

                                    if v_start == 'N/A' and v_end == 'N/A':
                                        versiones_afectadas = partes_cpe[5] if len(partes_cpe) > 5 else "Verificar manualmente"
                                    else:
                                        versiones_afectadas = f"Desde {v_start} hasta {v_end}"

                                    # Extraemos Versión Corregida
                                    version_corregida = match.get('versionEndExcluding', 'Revisar parche del fabricante')

                                    # Guardamos en TUS columnas
                                    df_resultados.at[index, 'Producto'] = producto
                                    df_resultados.at[index, 'Componente afectado'] = componente
                                    df_resultados.at[index, 'Versiones afectadas (general)'] = versiones_afectadas
                                    df_resultados.at[index, 'Versión corregida / recomendada'] = version_corregida

                                    encontro_cpe = True
                                    break # Rompemos el bucle interno de cpeMatch
                                if encontro_cpe: break # Rompemos el bucle de nodes
                            if encontro_cpe: break # 

            elif response.status_code in [403, 429]:
                print(f"[!] Rate Limit detectado. Pausa de seguridad de 10s...")
                time.sleep(10)

        except Exception as e:
            print(f"[-] Error procesando el {cve_id}: {e}")
            time.sleep(6)
    tabla_html = df_resultados.to_html(
    classes="w-full text-left border-collapse", 
    index=False, 
    border=0,
    justify="left")
    return tabla_html