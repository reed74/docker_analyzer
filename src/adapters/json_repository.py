import json
from dataclasses import asdict
from src.core.ports import AnalysisRepository
from src.core.domain import AssetReport, VulnerabilityReport

class JsonRepository(AnalysisRepository):
    """
    Guarda los informes de activos y vulnerabilidades en nuestros
    ficheros JSON personalizados.
    """
    
    def save_asset_report(self, report: AssetReport, output_path: str):
        """Guarda el informe de activos."""
        data_dict = asdict(report)
        try:
            with open(output_path, 'w', encoding='utf-8') as f:
                json.dump(data_dict, f, indent=4)
        except IOError as e:
            print(f"Error al escribir el JSON de activos: {e}")

    def save_vulnerability_report(self, report: VulnerabilityReport, output_path: str):
        """
        Guarda el informe de vulnerabilidades, AGRUPANDO los resultados
        por paquete y versión, como se solicitó.
        """
        
        grouped_vulns = {}
        for vuln in report.package_vulnerabilities:
            pkg_name = vuln.package_name
            pkg_ver = vuln.package_version
            
            if pkg_name not in grouped_vulns:
                grouped_vulns[pkg_name] = {}
            if pkg_ver not in grouped_vulns[pkg_name]:
                grouped_vulns[pkg_name][pkg_ver] = []
                
            # Convertimos la vulnerabilidad a dict 
            grouped_vulns[pkg_name][pkg_ver].append(asdict(vuln))
        
        # Creamos el diccionario final para guardar
        report_dict = {
            "image_name": report.image_name,
            "os_vulnerabilities": [asdict(v) for v in report.os_vulnerabilities],
            "package_vulnerabilities": grouped_vulns # Ya contiene dicts
        }
   
        try:
            with open(output_path, 'w', encoding='utf-8') as f:
                json.dump(report_dict, f, indent=4)
        except IOError as e:
            print(f"Error al escribir el JSON de vulnerabilidades: {e}")