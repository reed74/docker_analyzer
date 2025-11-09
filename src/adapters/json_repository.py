import json
from dataclasses import asdict
from src.core.ports import AnalysisRepository
from src.core.domain import AssetReport, VulnerabilityReport

class JsonRepository(AnalysisRepository):
    """
    Guarda los informes de activos y vulnerabilidades en ficheros JSON.
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
        """Guarda el informe de vulnerabilidades."""
        data_dict = asdict(report)
        try:
            with open(output_path, 'w', encoding='utf-8') as f:
                json.dump(data_dict, f, indent=4)
        except IOError as e:
            print(f"Error al escribir el JSON de vulnerabilidades: {e}")