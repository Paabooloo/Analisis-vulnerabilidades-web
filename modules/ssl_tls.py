import pandas as pd
import socket
import io
def ssl_tls(vulnerabilidad_detectada, archivo):
    df = pd.read_csv(io.StringIO(archivo))
    target = df['Target'].astype(str).str.strip()
    puerto = df['Port'].astype(str).str.strip()
    total_urls = len(target)  # Sin el -1 para que la barra de progreso llegue al 100%
    
    df_resultados = pd.DataFrame({
        'Target': target,
        'Puerto': puerto,
        'SSL 2.0': 'DEFAULT',
        'SSL 3.0': 'DEFAULT',
        'TLS 1.0': 'DEFAULT',
        'TLS 1.1': 'DEFAULT',
        'TLS 1.2': 'DEFAULT',
        'TLS 1.3': 'DEFAULT',
        'Correcto': '✅'
    })
    paquetes_bytes = {
    'SSL 2.0': {'index': 0, 'paquete': bytes.fromhex("802b0100020012000000100700c0030080010080060040040080020080030000040080aabbccddeeff11223344556677889900")},
    'SSL 3.0': {'index': 1, 'paquete': bytes.fromhex("160300002f0100002b030011223344556677889900aabbccddeeff11223344556677889900aabbccddeeff000004002f00350100")},
    'TLS 1.0': {'index': 2, 'paquete': bytes.fromhex("160301002f0100002b030111223344556677889900aabbccddeeff11223344556677889900aabbccddeeff000004002f00350100")},
    'TLS 1.1': {'index': 3, 'paquete': bytes.fromhex("160302002f0100002b030211223344556677889900aabbccddeeff11223344556677889900aabbccddeeff000004002f00350100")},
    'TLS 1.2': {'index': 4, 'paquete': bytes.fromhex("160303002f0100002b030311223344556677889900aabbccddeeff11223344556677889900aabbccddeeff000004002f00350100")},
    'TLS 1.3': {'index': 5, 'paquete': bytes.fromhex("16030100420100003e030311223344556677889900aabbccddeeff11223344556677889900aabbccddeeff000004002f003501000012002b000200020304")}
    }
   
    for index, (protocolo, paquete) in enumerate(paquetes_bytes.items()):
            for index, fila in df_resultados.iterrows():
                host = fila['Target']  # Usamos el target directo porque ya viene limpio

                try:
                    p_int = int(fila['Puerto'])
                except ValueError:
                    p_int = 443

                if not host or host == 'nan' or host.strip() == '':
                    df_resultados.at[index, 'Correcto'] = '❌ Error URL'
                    continue

                try:
                    # Conexión por socket crudo saltándonos las restricciones de Windows
                    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                    sock.settimeout(3)
                    sock.connect((host, p_int))

                    sock.sendall(paquete)
                    respuesta = sock.recv(5)
                    sock.close()

                    # Si el servidor cierra el canal sin responder nada
                    if not respuesta:
                        if protocolo in ['SSL 2.0', 'SSL 3.0', 'TLS 1.0', 'TLS 1.1']:
                            df_resultados.at[index, protocolo] = 'Seguro 🔒'
                        else:
                            df_resultados.at[index, protocolo] = 'No Soportado'
                            df_resultados.at[index, 'Correcto'] = '❌'
                        continue

                    tipo_registro = respuesta[0]

                    if tipo_registro == 22:  # 22 = Handshake aceptado por el servidor
                        if protocolo in ['SSL 2.0', 'SSL 3.0', 'TLS 1.0', 'TLS 1.1']:
                            df_resultados.at[index, protocolo] = 'VULNERABLE 🚨'
                            df_resultados.at[index, 'Correcto'] = '❌'
                        else:
                            df_resultados.at[index, protocolo] = 'Seguro 🔒'  # TLS 1.2 o 1.3 activo

                    elif tipo_registro == 21:  # 21 = Alerta (El servidor rechaza el protocolo)
                        if protocolo in ['SSL 2.0', 'SSL 3.0', 'TLS 1.0', 'TLS 1.1']:
                            df_resultados.at[index, protocolo] = 'Seguro 🔒'
                        else:
                            df_resultados.at[index, protocolo] = 'No Soportado'
                            df_resultados.at[index, 'Correcto'] = '❌'

                except (ConnectionResetError, socket.timeout):
                    # Si el servidor corta la conexión bruscamente o da timeout, ha rechazado el protocolo
                    if protocolo in ['SSL 2.0', 'SSL 3.0', 'TLS 1.0', 'TLS 1.1']:
                        df_resultados.at[index, protocolo] = 'Seguro 🔒'
                    else:
                        df_resultados.at[index, protocolo] = 'No Soportado'
                        df_resultados.at[index, 'Correcto'] = '❌'
                except Exception:
                    df_resultados.at[index, protocolo] = 'Error'
                    df_resultados.at[index, 'Correcto'] = '❌'
                

    print("                 🎯 RESULTADOS DE LA AUDITORÍA DE", vulnerabilidad_detectada,"                 \n")
    tabla_html = df_resultados.to_html(
    classes="w-full text-left border-collapse", 
    index=False, 
    border=0,
    justify="left"
)

    return tabla_html