import pandas as pd
import subprocess
import io

def security_policy(vulnerabilidad_detectada, archivo):
    df = pd.read_csv(io.StringIO(archivo))
    urls_limpias = df['Final URL'].astype(str).str.strip()
    df_resultados = pd.DataFrame({
    'URL final': urls_limpias,
    'CSP': 'DEFAULT',
    'BROAD': 'DEFAULT',
    'UNSAFE': 'DEFAULT',
    'Correcto': '✅'
    })

    for indice, url in urls_limpias.items():
        if url and url.lower() != 'nan':
            curl_csp = f'curl -I -s {url} | findstr /I"content-security-policy"'
            respuesta_csp = subprocess.run(curl_csp, shell=True, capture_output=True, text=True)
    
            salida_csp = respuesta_csp.stdout.strip().lower()
            
            if not salida_csp:
                df_resultados.at[indice, 'CSP'] = 'NO'
                df_resultados.at[indice, 'Correcto'] = '❌'
            else:
                df_resultados.at[indice, 'CSP'] = 'SI'

            #verificado  
            curl_unsafe = f'curl -I -s -L {url} | findstr /I "content-security-policy" | findstr /I /C:"unsafe-inline" /C:"unsafe-eval"'
            respuesta_unsafe = subprocess.run(curl_unsafe, shell=True, capture_output=True, text=True)
            salida_unsafe = respuesta_unsafe.stdout.strip().lower()
            
            if salida_unsafe:
                df_resultados.at[indice, 'UNSAFE'] = 'SI'
                df_resultados.at[indice, 'Correcto'] = '❌'

            else:
                df_resultados.at[indice, 'UNSAFE'] = 'NO'
            
            #verificado
            curl_broad = f'curl -I -s -L {url} | findstr /I "content-security-policy" | findstr /I /C:"*" /C:"http:" /C:"data:"'
            respuesta_broad = subprocess.run(curl_broad, shell=True, capture_output=True, text=True)
            salida_broad = respuesta_broad.stdout.strip().lower()
            if salida_broad:
                df_resultados.at[indice, 'BROAD'] = 'Usa comodines'
                df_resultados.at[indice, 'Correcto'] = '❌'
            else:
                df_resultados.at[indice, 'BROAD'] = 'BIEN'
        

    print("                 🎯 RESULTADOS DE LA AUDITORÍA DE", vulnerabilidad_detectada,"                 \n")
 
    tabla_html = df_resultados.to_html(
    classes="w-full text-left border-collapse", 
    index=False, 
    border=0,
    justify="left")
    return tabla_html