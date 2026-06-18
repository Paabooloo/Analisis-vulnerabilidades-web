import pandas as pd
import subprocess
import io
import pandas as pd
import subprocess

def webside(vulnerabilidad_detectada, archivo):
    df = pd.read_csv(io.StringIO(archivo))
    urls_limpias = df['Final URL'].astype(str).str.strip()
    total_urls = len(urls_limpias)  # Sin el -1 para que la barra de progreso llegue al 100%
    
    # Inicializamos el dataframe vacío o con 'FALTA' por defecto
    df_resultados = pd.DataFrame({
        'URL final': urls_limpias,
        'X-Content-Type-Options': 'DEFAULT',
        'X-XSS-Protection': 'DEFAULT',
        'X-Frame-Options': 'DEFAULT',
        'HSTS': 'DEFAULT',
        'HTTPS': 'DEFAULT',
        'Correcto': '✅'
    })
    
    for indice, url in urls_limpias.items():
    
        if url and str(url).lower() != 'nan':
            # 1. Comprobamos X-Frame-Options
            cmd_frame = f'curl -I -s {url} | findstr /I "x-frame-options"'
            res_frame = subprocess.run(cmd_frame, shell=True, capture_output=True, text=True)
            salida_frame = res_frame.stdout.strip()
            if "sameorigin" in salida_frame or "deny" in salida_frame:
                df_resultados.at[indice, 'X-Frame-Options'] = 'SI'
            elif salida_frame:
                df_resultados.at[indice, 'X-Frame-Options'] = 'INSEGURO'
                df_resultados.at[indice, 'Correcto'] = '❌'  
            else:
                df_resultados.at[indice, 'X-Frame-Options'] = 'INEXISTENTE'
                df_resultados.at[indice, 'Correcto'] = '❌'

            # 2. Comprobamos X-Content-Type-Options
            cmd_type = f'curl -I -s {url} | findstr /I "x-content-type-options"'
            res_type = subprocess.run(cmd_type, shell=True, capture_output=True, text=True)
            salida_type = res_type.stdout.strip()
            if "nosniff" in salida_type:
                df_resultados.at[indice, 'X-Content-Type-Options'] = 'BIEN'
            elif salida_type:
                df_resultados.at[indice, 'X-Content-Type-Options'] = 'MAL'
                df_resultados.at[indice, 'Correcto'] = '❌'
            else:
                df_resultados.at[indice, 'X-Content-Type-Options'] = 'INEXISTENTE'
                df_resultados.at[indice, 'Correcto'] = '❌'


            cmd_hsts = f'curl -I -s {url} | findstr /I "strict-transport-security"'
            res_hsts = subprocess.run(cmd_hsts, shell=True, capture_output=True, text=True)
            salida_hsts = res_hsts.stdout.strip()
            
            if "max-age=" in salida_hsts:
                df_resultados.at[indice, 'HSTS'] = 'BIEN'
            elif salida_type:
                df_resultados.at[indice, 'HSTS'] = 'MAL'
                df_resultados.at[indice, 'Correcto'] = '❌'
            else:
                df_resultados.at[indice, 'HSTS'] = 'INEXISTENTE'
                df_resultados.at[indice, 'Correcto'] = '❌'
         

            cmd_xss = f'curl -I -s "{url}" | tr "[:upper:]" "[:lower:]" | grep "x-xss-protection"'
            res_xss = subprocess.run(cmd_xss, shell=True, capture_output=True, text=True)
            salida_xss = res_xss.stdout.strip()
            if salida_xss:
                df_resultados.at[indice, 'X-XSS-Protection'] = 'BIEN'
            else:
                df_resultados.at[indice, 'X-XSS-Protection'] = 'MAL'
                df_resultados.at[indice, 'Correcto'] = '❌'
            
            cmd_https= f'curl -I -s "{url}" | findstr /I /C:"HTTP/" /C:"Location:"'
            res_https = subprocess.run(cmd_https, shell=True, capture_output=True, text=True)
            salida_https = res_https.stdout.strip()
            salida_http_lower = salida_https.lower()

            if "location: https://" in salida_http_lower:
                df_resultados.at[indice, 'HTTPS'] = 'BIEN'

            elif "http/" in salida_http_lower and " 200 " in salida_http_lower:
                df_resultados.at[indice, 'HTTPS'] = 'MAL'
                df_resultados.at[indice, 'Correcto'] = '❌'
            else:
                df_resultados.at[indice, 'HTTPS'] = 'INACCESIBLE'
                df_resultados.at[indice, 'Correcto'] = '❌'
    print("                 🎯 RESULTADOS DE LA AUDITORÍA DE", vulnerabilidad_detectada,"                 \n")
    tabla_html = df_resultados.to_html(
    classes="w-full text-left border-collapse", 
    index=False, 
    border=0,
    justify="left")
    return tabla_html
    