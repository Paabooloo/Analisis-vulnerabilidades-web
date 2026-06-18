from fastapi import FastAPI, UploadFile, File, Form
from fastapi.responses import HTMLResponse, FileResponse 
import pandas as pd
import io
from modules.vulnerabilidades import vulnerabilidades
from modules.derivar import derivar
from modules.ping import ping
from modules.tabla import tabla
# Importa aquí tus funciones actuales. Por ejemplo:
# from mis_scripts import escanear_vulnerabilidades, buscar_cves, hacer_ping

app = FastAPI()

# --- AÑADE ESTO ---
@app.get("/")
async def mostrar_panel_web():
    # Esto lee tu archivo index.html y lo muestra en el navegador
    return FileResponse("index.html")
# ------------------


@app.post("/procesar", response_class=HTMLResponse)
async def procesar_formulario(
    tipoAnalisis: str = Form(...), 
    archivoCsv: UploadFile = File(...)
):
    contenido_bytes = await archivoCsv.read()
    archivo = contenido_bytes.decode("utf-8", errors="ignore")
    nombre_del_archivo = archivoCsv.filename
   
    if tipoAnalisis == "vulnerabilidades":
        vulnerabilidad_detectada = vulnerabilidades(nombre_del_archivo)
     
        if vulnerabilidad_detectada is None:
            resultados_consola = "No se detectaron vulnerabilidades en este archivo."
        else:
            resultados_consola = vulnerabilidad_detectada
        
        resultados_consola = derivar(vulnerabilidad_detectada, archivo)
        

    elif tipoAnalisis == "cve":
      vulnerabilidad_detectada = vulnerabilidades(nombre_del_archivo)
      resultados_consola = tabla(archivo)
    
        

    elif tipoAnalisis == "ping":
        vulnerabilidad_detectada = "PING"     
        resultados_consola = ping(archivo)
        

 
    html_respuesta = f"""
    <!DOCTYPE html>
    <html lang="es">
    <style>
       .tabla-seguridad {{ border-collapse: collapse; 
            width: 100%; /* Asegura que la tabla ocupe todo el ancho */
            table-layout: fixed; /* ¡ESTA ES LA CLAVE! Fuerza columnas de igual tamaño */}}
            border-style: solid;
            border-color: black;
            border-collapse: separate;
            border-spacing: 20px 0; /* 20px de espacio horizontal entre columnas */
        
        .tabla-seguridad th {{
            background-color: #1f2937;
            color: #9ca3af;
            font-weight: 600; 
        }}
        
        .tabla-seguridad td. .tabla-seguridad th {{
          padding: 15px 30px;
            border-bottom: 1px solid #374151;
            color: #e5e7eb;
            text-align: center;
            overflow: hidden; /* Corta si se sale */
            text-overflow: ellipsis; /
        }}
        
        .tabla-seguridad tr:hover td {{
            background-color: #374151;
        }}
    </style>
    <head>
        <meta charset="UTF-8">
        <title>Resultados del Análisis</title>
        <script src="https://cdn.tailwindcss.com"></script>
    </head>
    <body class="bg-gray-100 p-10 font-sans flex justify-center min-h-screen">
        <div class="max-w-7xl w-full bg-white p-8 rounded-xl shadow-2xl flex flex-col">
            <h1 class="text-3xl font-bold text-blue-700 mb-6 border-b pb-4">Reporte de Análisis</h1>
            
            <div class="mb-4">
                <span class="font-bold text-gray-700">Tipo de escaneo: </span> 
                <span class="bg-blue-100 text-blue-800 px-3 py-1 rounded-full text-sm uppercase font-semibold">
                    {vulnerabilidad_detectada}
                </span>
            </div>
            
            <div class="bg-gray-800 text-gray-200 p-6 rounded-lg shadow-inner flex-grow">
                {resultados_consola}
            </div>
            
            <div class="mt-8 flex justify-between items-center">
                <a href="/" class="bg-gray-200 hover:bg-gray-300 text-gray-800 font-bold py-2 px-5 rounded-lg transition-colors shadow">
                    &larr; Volver al panel
                </a>
            </div>
        </div>
    </body>
    </html>
    """
    
    return HTMLResponse(content=html_respuesta)
    
   