import json
from collections import Counter
from src.core.domain import VulnerabilityReport

class SummaryAdapter:
    """
    Toma un informe de vulnerabilidades y genera un JSON
    simple con el conteo total y por severidad.
    """
    
    def save(self, vuln_report: VulnerabilityReport, output_path: str):
        
        # Combina las vulnerabilidades de paquetes y de SO
        all_vulns = vuln_report.os_vulnerabilities + vuln_report.package_vulnerabilities
        
        # Usa un Counter para contar por severidad
        severity_counts = Counter()
        for vuln in all_vulns:
            # Normalizamos la severidad
            severity = str(vuln.severity).upper() if vuln.severity else "UNKNOWN"
            
            if severity == "NEGLIGIBLE":
                severity = "NONE"
            elif severity not in ["CRITICAL", "HIGH", "MEDIUM", "LOW", "NONE"]:
                severity = "UNKNOWN"
                
            severity_counts[severity] += 1

        # Prepara el diccionario de resumen
        summary_data = {
            "total_vulnerabilities": len(all_vulns),
            "severity_counts": {
                "critical": severity_counts.get("CRITICAL", 0),
                "high": severity_counts.get("HIGH", 0),
                "medium": severity_counts.get("MEDIUM", 0),
                "low": severity_counts.get("LOW", 0),
                "none": severity_counts.get("NONE", 0),
                "unknown": severity_counts.get("UNKNOWN", 0)
            }
        }
        
        # Escribe el fichero JSON
        try:
            with open(output_path, 'w', encoding='utf-8') as f:
                json.dump(summary_data, f, indent=4)
        except IOError as e:
            print(f"Error al escribir el JSON de resumen: {e}")