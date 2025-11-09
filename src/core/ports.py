from abc import ABC, abstractmethod
from typing import List, Tuple
from .domain import Package, Binary, Vulnerability, AssetReport, VulnerabilityReport

class ImageDataProvider(ABC):
    """Puerto para obtener datos de una imagen (Syft)."""
    @abstractmethod
    def get_packages(self, image_name: str) -> List[Package]: ...
        
    @abstractmethod
    def get_non_package_binaries(self, image_name: str) -> List[Binary]: ...
    
    @abstractmethod
    def get_os_info(self, image_name: str) -> Tuple[str, str]: ...


class AnalysisRepository(ABC):
    """Puerto para guardar los informes de análisis."""
    
    @abstractmethod
    def save_asset_report(self, report: AssetReport, output_path: str):
        ...
        
    @abstractmethod
    def save_vulnerability_report(self, report: VulnerabilityReport, output_path: str):
        ...

class CveRepository(ABC):
    """Puerto para un adaptador que busca vulnerabilidades."""
    
    @abstractmethod
    def find_package_vulnerabilities(self, packages: List[Package]) -> List[Vulnerability]:
        ...
        
    @abstractmethod
    def find_os_vulnerabilities(self, os_name: str, os_version: str) -> List[Vulnerability]:
        ...