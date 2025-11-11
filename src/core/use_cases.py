from .ports import ImageDataProvider, CveRepository
from .domain import AssetReport, VulnerabilityReport
from typing import Tuple

class ImageAnalyzerService:
    
    def __init__(
        self, 
        data_provider: ImageDataProvider, 
        cve_repo: CveRepository
    ):
        self._provider = data_provider
        self._cve_repo = cve_repo

    def analyze_image(self, image_name: str) -> Tuple[AssetReport, VulnerabilityReport]:
        """
        Lógica principal de análisis. Devuelve un informe de activos
        y un informe de vulnerabilidades.
        """
        print(f"Iniciando análisis de {image_name}...")
        
        # --- 1. Obtener Activos ---
        packages = self._provider.get_packages(image_name)
        print(f"Encontrados {len(packages)} paquetes.")
        
        binaries = self._provider.get_non_package_binaries(image_name)
        print(f"Encontrados {len(binaries)} binarios sin paquete.")
        
        os_name, os_version = self._provider.get_os_info(image_name)
        print(f"Sistema Operativo detectado: {os_name}:{os_version}")

        # --- 2. Crear el Informe de Activos (SBOM) ---
        asset_report = AssetReport(
            image_name=image_name,
            os_name=os_name,
            os_version=os_version,
            packages=packages,
            non_package_binaries=binaries
        )

        # --- 3. Obtener Vulnerabilidades ---
        pkg_vulns = self._cve_repo.find_package_vulnerabilities(packages)
        print(f"Encontradas {len(pkg_vulns)} vulnerabilidades de paquetes en tu BD.")
        
        os_vulns = self._cve_repo.find_os_vulnerabilities(os_name, os_version)
        print(f"Encontradas {len(os_vulns)} vulnerabilidades del SO en tu BD.")
        
        # --- 4. Crear el Informe de Vulnerabilidades (VEX) ---
        vuln_report = VulnerabilityReport(
            image_name=image_name,
            os_vulnerabilities=os_vulns,
            package_vulnerabilities=pkg_vulns # La lista plana
        )

        # --- 5. Devolver ambos informes ---
        return asset_report, vuln_report