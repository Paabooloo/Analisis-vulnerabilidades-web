import pandas as pd
import io
import subprocess
import platform

def ping(archivo):
    df = pd.read_csv(io.StringIO(archivo))
    df_resultados = pd.DataFrame({
        'Pagina': df.get('Target'),
        'Estado': '',
        'IP': df.get('Ip address'),
        'Estado IP': '',
        'Dominio': df.get('Domain'),
        'Estado Dominio': '',
        'Correcto': '✅'
    })
    columnas_presentes = []

    if 'Ip address' not in df.columns:
        df_resultados.drop(columns=['IP', 'Estado_IP'], inplace=True)
    else:
        columnas_presentes.append('Ip address')
        
    if 'Target' not in df.columns:
        df_resultados.drop(columns=['Target', 'Estado_Target'], inplace=True)
    else:
        columnas_presentes.append('Target')
        
    if 'Domain' not in df.columns:
        df_resultados.drop(columns=['Dominio', 'Estado_Dominio'], inplace=True)
    else:
        columnas_presentes.append('Domain')

    # Si terminamos quitando todo, avisamos al usuario
    if not columnas_presentes:
        return "<p class='text-red-500'>Error: El archivo no tiene IP, Target ni Dominio.</p>"

    # Detectamos el sistema operativo
    parametro_ping = "-n" if platform.system().lower() == "windows" else "-c"

    # 3. Recorremos fila por fila
    for index, row in df.iterrows():
        hubo_error_en_fila = False

        # --- VERIFICACIÓN IP ---
        if 'Ip address' in columnas_presentes:
            ip_actual = str(row['Ip address']).strip()
            res_ip = subprocess.run(f'ping {parametro_ping} 1 {ip_actual}', shell=True, capture_output=True)
            if res_ip.returncode == 0:
                df_resultados.at[index, 'Estado_IP'] = '✅ Online'
            else:
                df_resultados.at[index, 'Estado_IP'] = '❌ Offline'
                hubo_error_en_fila = True

        # --- VERIFICACIÓN TARGET ---
        if 'Target' in columnas_presentes:
            target_actual = str(row['Target']).strip()
            res_target = subprocess.run(f'ping {parametro_ping} 1 {target_actual}', shell=True, capture_output=True)
            if res_target.returncode == 0:
                df_resultados.at[index, 'Estado_Target'] = '✅ Online'
            else:
                df_resultados.at[index, 'Estado_Target'] = '❌ Offline'
                hubo_error_en_fila = True

        # --- VERIFICACIÓN DOMINIO ---
        if 'Domain' in columnas_presentes:
            dominio_actual = str(row['Domain']).strip()
            res_dominio = subprocess.run(f'ping {parametro_ping} 1 {dominio_actual}', shell=True, capture_output=True)
            if res_dominio.returncode == 0:
                df_resultados.at[index, 'Estado_Dominio'] = '✅ OKEY'
            else:
                df_resultados.at[index, 'Estado_Dominio'] = '❌ NO'
                hubo_error_en_fila = True

        # --- COLUMNA GLOBAL DE CONTROL ---
        if hubo_error_en_fila:
            df_resultados.at[index, 'Correcto'] = '❌'

   
    tabla_html = df_resultados.to_html(
        classes="w-full text-left text-gray-200 border-collapse", 
        index=False, 
        border=0,
        justify="left",
        escape=False
    )
    
    return tabla_html