def vulnerabilidades(nombre_del_archivo):
    mapa_vulnerabilidades = {
        # ---------------------------------------------------------
        # CATEGORÍA: APPLICATION SECURITY (Seguridad de Aplicaciones)
        # ---------------------------------------------------------
        "csp_no_policy_v2": "Content Security Policy (CSP) Missing",
        "csp_too_broad_v2": "Content Security Policy (CSP) Missing",
        "csp_unsafe_policy_v2": "Content Security Policy (CSP) Missing",
        "csp_unsafe_directive": "Content Security Policy Contains 'unsafe-*' Directive",
        "csp_broad_directive": "Content Security Policy Contains Broad Directives",
        "x_content_type_options_incorrect": "Website does not implement X-Content-Type-Options Best Practices",
        "hsts_incorrect": "Website Does Not Implement HSTS Best Practices",
        "unsafe_sri_v2": "Unsafe Implementation Of Subresource Integrity",
        "https_not_enforced": "Site does not enforce HTTPS",
        "x_xss_protection_incorrect": "Website does not implement X-XSS-Protection Best Practices",
        "x_frame_options_incorrect": "Website does not implement X-Frame-Options Best Practices",

        # ---------------------------------------------------------
        # CATEGORÍA: NETWORK SECURITY & SSL/TLS (Seguridad de Red)
        # ---------------------------------------------------------
        "ssl_weak_protocol": "SSL/TLS Service Supports Weak Protocol",
        "tls_weak_protocol": "SSL/TLS Service Supports Weak Protocol",
        "tls_weak_cipher": "SSL/TLS Service Supports Weak Protocol",
        "ssl_weak_cipher": "SSL/TLS Service Supports Weak Protocol",
        "certificate_expired": "Certificate Is Expired",
        "tls_cert_no_revocation": "Certificate Without Revocation Control",
        "certificate_weak_signature": "Certificate Has A Weak Signature Algorithm",
        "open_port": "Unsafe Open Port Detected",

        # ---------------------------------------------------------
        # CATEGORÍA: PATCHING CADENCE & CVSS (Gestión de Parches)
        # ---------------------------------------------------------
        # Nota: En vulnerabilidades CVSS, a veces el archivo incluye el slug literal larguísimo
        "service_vuln_host_v3_critical": "Critical-Severity CVSS v3.0 Service Vulnerability in Last Observation",
        "service_vuln_host_v3_high": "High-Severity CVSS v3.0 Service Vulnerability in Last Observation",
        "service_vuln_host_v3_medium": "Medium-Severity CVSS v3.0 Service Vulnerability in Last Observation",
        "service_vuln_host_v3_low": "Low-Severity CVSS v3.0 Service Vulnerability in Last Observation",
        "patching_cadence_v3_critical": "Critical-Severity CVSS v3.0 Vulnerability Patching Cadence",
         
        
        # ---------------------------------------------------------
        # CATEGORÍA: DNS HEALTH (Salud del DNS)
        # ---------------------------------------------------------
        "spf_record_missing": "SPF Record Missing",
        "spf_record_malformed": "SPF Record Malformed",
        "spf_record_softfail": "SPF Record Includes SoftFail",
        "dkim_record_missing": "DKIM Record Missing",
        "dmarc_record_missing": "DMARC Record Missing",
        "dmarc_policy_none": "DMARC Record Policy Is 'none'",
        "dnssec_missing": "DNSSEC Not Enabled",

        # ---------------------------------------------------------
        # CATEGORÍA: ENDPOINT SECURITY & OTROS
        # ---------------------------------------------------------
        "outdated_browser": "Outdated Browser",
        "outdated_os": "Outdated Operating System",
        "malware_infection": "Malware Infection Detected"
    }
   # --- LA LÍNEA CLAVE QUE TE FALTA ---
    # Le damos un valor por defecto por si el archivo está limpio
    vulnerabilidad_detectada = None 
    # -----------------------------------
    
    # Pasamos todo a minúsculas
    texto_minusculas = nombre_del_archivo.lower()
    
    for codigo, nombre_real in mapa_vulnerabilidades.items():
        if codigo.lower() in texto_minusculas:
            vulnerabilidad_detectada = nombre_real
            break

    return vulnerabilidad_detectada