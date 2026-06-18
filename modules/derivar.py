from modules.practicas import webside
from modules.policy import security_policy
from modules.ssl_tls import ssl_tls
from modules.inseguro import inseguro
from modules.cves import cves
def derivar(vulnerabilidad_detectada, archivo):
    match vulnerabilidad_detectada:
        case "Content Security Policy (CSP) Missing":
           print("🚀 Comprobando: Content Security Policy (CSP) Missing...")
           tabla_pandas = security_policy(vulnerabilidad_detectada, archivo)
           return tabla_pandas
           
        case "Content Security Policy Contains 'unsafe-*' Directive":
            print("🚀 Comprobando: Content Security Policy Contains 'unsafe-*' Directive...")
            tabla_pandas = security_policy(vulnerabilidad_detectada, archivo)
            return tabla_pandas

        case "csp_too_broad_v2":
            print("🚀 Comprobando: Content Security Policy Contains Broad Directives...")
            tabla_pandas = security_policy(vulnerabilidad_detectada, archivo)
            return tabla_pandas

        case "Website does not implement X-Content-Type-Options Best Practices":
            print("🚀 Comprobando: Website does not implement X-Content-Type-Options Best Practices...")
            tabla_pandas = webside(vulnerabilidad_detectada, archivo)
            return tabla_pandas
            
            
        case "Website Does Not Implement HSTS Best Practices":
            print("🚀 Comprobando: Website Does Not Implement HSTS Best Practices...")
            tabla_pandas = webside(vulnerabilidad_detectada, archivo)
            return tabla_pandas
            
        case "Unsafe Implementation Of Subresource Integrity":
            print("🚀 Comprobando: Unsafe Implementation Of Subresource Integrity...")
            tabla_pandas = inseguro(vulnerabilidad_detectada, archivo)
            return tabla_pandas
            
        case "Site does not enforce HTTPS":
            print("🚀 Comprobando: Site does not enforce HTTPS...")
            tabla_pandas = webside(vulnerabilidad_detectada, archivo)
            return tabla_pandas

        case "Website does not implement X-XSS-Protection Best Practices":
            print("🚀 Comprobando: Website does not implement X-XSS-Protection Best Practices...")
            tabla_pandas = webside(vulnerabilidad_detectada, archivo)
            return tabla_pandas
            
        case "Website does not implement X-Frame-Options Best Practices":
            print("🚀 Comprobando: Website does not implement X-Frame-Options Best Practices...")
            tabla_pandas = webside(vulnerabilidad_detectada, archivo)
            return tabla_pandas

        case "SSL/TLS Service Supports Weak Protocol":
            print("🚀 Comprobando: SSL/TLS Service Supports Weak Protocol...")
            tabla_pandas = ssl_tls(vulnerabilidad_detectada, archivo)
            return tabla_pandas

        case "Certificate Is Expired":
            print("🚀 Comprobando: Certificate Is Expired...")
            
        case "Certificate Without Revocation Control":
            print("🚀 Comprobando: Certificate Without Revocation Control...")
            
        case "Certificate Has A Weak Signature Algorithm":
            print("🚀 Comprobando: Certificate Has A Weak Signature Algorithm...")
            
        case "Unsafe Open Port Detected":
            print("🚀 Comprobando: Unsafe Open Port Detected...")
            
        case "Critical-Severity CVSS v3.0 Service Vulnerability in Last Observation":
            print("🚀 Comprobando: Critical-Severity CVSS v3.0 Service Vulnerability in Last Observation...")
            tabla_pandas = cves(vulnerabilidad_detectada, archivo)
            return tabla_pandas
            

        case "High-Severity CVSS v3.0 Service Vulnerability in Last Observation":
            print("🚀 Comprobando: High-Severity CVSS v3.0 Service Vulnerability in Last Observation...")
            tabla_pandas = cves(vulnerabilidad_detectada, archivo)
            return tabla_pandas
        
        case "Medium-Severity CVSS v3.0 Service Vulnerability in Last Observation":
            print("🚀 Comprobando: Medium-Severity CVSS v3.0 Service Vulnerability in Last Observation...")
            tabla_pandas = cves(vulnerabilidad_detectada, archivo)
            return tabla_pandas
        
        case "Low-Severity CVSS v3.0 Service Vulnerability in Last Observation":
            print("🚀 Comprobando: Low-Severity CVSS v3.0 Service Vulnerability in Last Observation...")
            tabla_pandas = cves(vulnerabilidad_detectada, archivo)
            return tabla_pandas
        
        case "Critical-Severity CVSS v3.0 Vulnerability Patching Cadence":
            print("🚀 Comprobando: Critical-Severity CVSS v3.0 Vulnerability Patching Cadence...")
            tabla_pandas = cves(vulnerabilidad_detectada, archivo)
            return tabla_pandas