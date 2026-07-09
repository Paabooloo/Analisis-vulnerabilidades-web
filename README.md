# Analisis-vulnerabilidades-web

Herramienta web interna diseñada para optimizar el triaje en el Centro de Operaciones de Seguridad (SOC). La herramienta permite a los miembros de la OTS subir un archivo CSV de la pagina web https://platform.securityscorecard.io/ la cual utilizan ciertos clientes para auditarnos. 
Automatiza la verificación de cada línea para confirmar si el reporte de scorecard es correcto o si por el contrario ha sido un falso positivo.

Por motivos de seguridad corporativa y protección de la infraestructura interna, el acceso a esta herramienta está restringido a nivel de servidor operando bajo un modelo de IP Allowlisting.

## ✨ Características Principales

*   **Procesamiento de CSV:** Interfaz minimalista que permite la carga directa de archivos CSV con listados de vulnerabilidades reportadas.
*   **Validación Automatizada:** El backend lee el archivo y ejecuta comprobaciones activas sobre los objetivos listados para verificar el estado real de la vulnerabilidad (cabeceras, configuración SSL, puertos expuestos, etc.).
*   **Filtrado de Falsos Positivos:** Identifica y descarta automáticamente las alertas que no suponen un riesgo real, ahorrando tiempo de análisis manual.
*   **Control de Acceso por Red:** La aplicación rechaza cualquier conexión HTTP/HTTPS que no provenga de las direcciones IP internas autorizadas del SOC, garantizando que la herramienta no esté expuesta públicamente.

## 🛠️ Stack Tecnológico

*   **Backend:** Python 3.14, FastAPI
*   **Procesamiento de Datos:** `pandas` / `csv` (para la lectura y manipulación del archivo subido)
*   **Frontend:** HTML puro, CSS básico
*   **Seguridad y Despliegue:** Render

*   ## ⚠️ Aviso Legal / Disclaimer

Este software ha sido desarrollado exclusivamente para uso interno y auditoría defensiva de activos corporativos propios. El uso de esta herramienta para verificar objetivos externos sin autorización está prohibido. El código se comparte con fines de demostración técnica.

## 👨‍💻 Autor

*   **Pablo López Jiménez** - Analista de Ciberseguridad
*   Linkedin: www.linkedin.com/in/pablo-lópez-jiménez-248b8433a
