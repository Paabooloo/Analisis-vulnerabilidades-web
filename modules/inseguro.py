import requests
import pandas as pd
from bs4 import BeautifulSoup
import io
from urllib.parse import urljoin
def inseguro(vulnerabilidad_detectada, archivo):
    df = pd.read_csv(io.StringIO(archivo))
    urls_limpias = df['Domain'].astype(str).str.strip()
    total_urls = len(urls_limpias)
    df_resultados = pd.DataFrame({
        'URL final': urls_limpias,
        'SRI': 'DEFAULT',
        
        'Correcto': '✅'
    })
    
    headers = {

        'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36'
    }
    for index, url in enumerate(urls_limpias):
        if not url or url == 'nan' or url == '':
            df_resultados.at[index, 'SRI'] = 'No Soportado'
            df_resultados.at[index, 'Correcto'] = '❌'
            continue
            
        url_peticion = url if url.startswith(('http://', 'https://')) else 'https://' + url

        try:
            response = requests.get(url_peticion, headers=headers, timeout=8)
            
            if response.status_code != 200:
                df_resultados.at[index, 'SRI'] = 'No Soportado'
                df_resultados.at[index, 'Correcto'] = '❌'
                continue

            soup = BeautifulSoup(response.text, 'html.parser')
            scripts = soup.find_all('script', src=True)
            implementacion_sri = 'Seguro 🔒'

            for script in scripts:
                src = script['src']
                url_absoluta = urljoin(url_peticion, src)
                
                # Ignorar scripts locales (no requieren SRI)
                if url_absoluta.startswith(url_peticion):
                    continue
                tiene_integrity = script.has_attr('integrity')
                tiene_crossorigin = script.has_attr('crossorigin') and script['crossorigin'].lower() == 'anonymous'

                if not tiene_integrity or not tiene_crossorigin:
                    implementacion_sri = 'No Soportado'
                    break 

            if implementacion_sri == 'Seguro 🔒':
                df_resultados.at[index, 'SRI'] = 'Seguro 🔒'
            else:
                df_resultados.at[index, 'SRI'] = 'No Soportado'
                df_resultados.at[index, 'Correcto'] = '❌'
                
        except requests.exceptions.RequestException:
            df_resultados.at[index, 'SRI'] = 'No Soportado'
            df_resultados.at[index, 'Correcto'] = '❌'

    print("                 🎯 RESULTADOS DE LA AUDITORÍA DE", vulnerabilidad_detectada,"                 \n")
    tabla_html = df_resultados.to_html(
    classes="w-full text-left border-collapse", 
    index=False, 
    border=0,
    justify="left")
    return tabla_html