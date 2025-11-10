from dataclasses import dataclass, field
from typing import List, Dict, Optional

@dataclass
class Package:
    name: str
    version: str
    vendor: str
    product: str
    layer_id: str
    layer_index: int

@dataclass
class Binary:
    path: str
    layer_id: str
    layer_index: int

@dataclass
class Vulnerability:
    cve_id: str
    package_name: str
    package_version: str
    severity: str

@dataclass
class AssetReport:
    """Contiene el inventario de activos (SBOM)."""
    image_name: str
    os_name: str
    os_version: str
    packages: List[Package]
    non_package_binaries: List[Binary]


@dataclass
class VulnerabilityReport:
    """Contiene los hallazgos de vulnerabilidades."""
    image_name: str
    os_vulnerabilities: List[Vulnerability]
    # El diccionario agrupado que pediste:
    package_vulnerabilities: Dict[str, Dict[str, List[Vulnerability]]]

class ImageAnalysisError(Exception):
    """Excepción base para errores durante el análisis de la imagen."""
    pass