from .ports import ImageDataProvider, AnalysisRepository, CveRepository
from .domain import AssetReport, VulnerabilityReport # Nuevos modelos

class ImageAnalyzerService:
    
    def __init__(
        self, 
        data_provider: ImageDataProvider, 
        json_repo: AnalysisRepository,
        cve_repo: CveRepository
    ):
        self._provider = data_provider
        self._json_repo = json_repo
        self._cve_repo = cve_repo

    def analyze_image(self, image_name: str, asset_path: str, vuln_path: str):
        """
        Lógica principal actualizada para generar dos informes.
        """
        print(f"Iniciando análisis de {image_name}...")
        
        # --- 1. Obtener Activos ---
        packages = self._provider.get_packages(image_name)
        print(f"Encontrados {len(packages)} paquetes.")
        
        binaries = self._provider.get_non_package_binaries(image_name)
        print(f"Encontrados {len(binaries)} binarios sin paquete.")
        
        os_name, os_version = self._provider.get_os_info(image_name)
        print(f"Sistema Operativo detectado: {os_name}:{os_version}")

        # --- 2. Crear y Guardar el Informe de Activos (SBOM) ---
        asset_report = AssetReport(
            image_name=image_name,
            os_name=os_name,
            os_version=os_version,
            packages=packages,
            non_package_binaries=binaries
        )
        self._json_repo.save_asset_report(asset_report, asset_path)
        print(f"Reporte de activos guardado en {asset_path}")

        # --- 3. Obtener Vulnerabilidades ---
        pkg_vulns = self._cve_repo.find_package_vulnerabilities(packages)
        print(f"Encontradas {len(pkg_vulns)} vulnerabilidades de paquetes en tu BD.")
        
        os_vulns = self._cve_repo.find_os_vulnerabilities(os_name, os_version)
        print(f"Encontradas {len(os_vulns)} vulnerabilidades del SO en tu BD.")

        # --- 4. Lógica de Agrupación  ---
        grouped_vulns = {}
        for vuln in pkg_vulns:
            pkg_name = vuln.package_name
            pkg_ver = vuln.package_version
            
            # Asegura que el diccionario para el paquete exista
            if pkg_name not in grouped_vulns:
                grouped_vulns[pkg_name] = {}
            
            # Asegura que la lista para esa versión exista
            if pkg_ver not in grouped_vulns[pkg_name]:
                grouped_vulns[pkg_name][pkg_ver] = []
                
            # Añade la vulnerabilidad
            grouped_vulns[pkg_name][pkg_ver].append(vuln)
        
        # --- 5. Crear y Guardar el Informe de Vulnerabilidades ---
        vuln_report = VulnerabilityReport(
            image_name=image_name,
            os_vulnerabilities=os_vulns,
            package_vulnerabilities=grouped_vulns # El diccionario agrupado
        )
        self._json_repo.save_vulnerability_report(vuln_report, vuln_path)
        print(f"Reporte de vulnerabilidades guardado en {vuln_path}")