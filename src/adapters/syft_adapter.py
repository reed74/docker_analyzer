import subprocess
import json
import re
from typing import List, Dict, Any, Optional, Tuple

from src.core.ports import ImageDataProvider
from src.core.domain import Package, Binary

def _parse_cpe(cpe_string: str) -> Tuple[Optional[str], Optional[str]]:
    """
    Función helper para extraer (vendor, product) de una cadena CPE 2.3.
    Formato: cpe:2.3:part:vendor:product:version...
    """
    try:
        parts = cpe_string.split(':')
        if len(parts) >= 6: 
            vendor = parts[3]
            product = parts[4]
            return vendor, product
    except Exception:
        pass 
    return None, None

class SyftAdapter(ImageDataProvider):
    
    def __init__(self):
        self._packages_cache: Optional[List[Package]] = None
        self._binaries_cache: Optional[List[Binary]] = None
        self._os_name_cache: Optional[str] = None
        self._os_version_cache: Optional[str] = None
        self._last_image_scanned: Optional[str] = None

    def _get_syft_json(self, image_name: str) -> Dict[str, Any]:
        """
        Ejecuta syft y devuelve la salida JSON parseada.
        Devuelve {} si falla, nunca None.
        """
        print(f"Ejecutando syft para {image_name}... (esto puede tardar un momento)")
        try:
            cmd = ["syft", "scan", f"docker:{image_name}", "-o", "json", "-s", "all-layers"]
            result = subprocess.run(
                cmd, capture_output=True, text=True, check=True, encoding="utf-8"
            )
            return json.loads(result.stdout)
        except FileNotFoundError:
            print("Error: 'syft' no se encuentra. ¿Está instalado y en el PATH?")
            raise
        except subprocess.CalledProcessError as e:
            print(f"Error al ejecutar syft: {e.stderr}")
            return {} 
        except Exception as e:
            print(f"Un error inesperado ocurrió en _get_syft_json: {e}")
            return {}

    def _run_scan_if_needed(self, image_name: str):
        """
        Función interna que ejecuta el análisis de syft y procesa los datos,
        pero solo si no se ha hecho ya para esta imagen.
        """
        if self._last_image_scanned == image_name:
            return

        print(f"Analizando datos de Syft para {image_name}...")
        data = self._get_syft_json(image_name)
        
        # --- Capturar Distro ---
        os_name = "unknown"
        os_version = "unknown"
        if data.get("distro"):
            os_name = data["distro"].get("name", "unknown")
            os_version = data["distro"].get("version", "unknown")
            
        self._os_name_cache = os_name
        self._os_version_cache = os_version
        
        layer_hash_to_index_map = {}
        if data.get("source", {}).get("layers"):
            for index, layer_data in enumerate(data["source"]["layers"]):
                layer_hash = layer_data.get("digest")
                if layer_hash:
                    layer_hash_to_index_map[layer_hash] = index

        packages = []
        non_package_binaries = []
        
        os_package_types = {"apk", "deb", "dpkg", "rpm"}

        if data.get("artifacts"):
            for artifact in data.get("artifacts"):
                pkg_type = artifact.get("type")
                name = artifact.get("name")
                version = artifact.get("version")
                locations = artifact.get("locations")
                cpe_list = artifact.get("cpes", []) 

                if not (name and version and locations):
                    continue  

                location = locations[0]
                path = location.get("path")
                layer_id_hash = location.get("layerID", "unknown")
                layer_index = layer_hash_to_index_map.get(layer_id_hash, -1)

                if pkg_type in os_package_types:
                    
                    vendor_str, product_str = None, None
                    if cpe_list:
                        # 1. Intentamos parsear el CPE primero
                        vendor_str, product_str = _parse_cpe(cpe_list[0])
                    
                    if not vendor_str:
                        # 2. Si falla (sin CPE), usamos el SO como vendor
                        vendor_str = os_name.lower().split()[0] # 'debian'
                    if not product_str:
                        # 3. El producto es siempre el nombre del paquete
                        product_str = name # 'apt' o 'openssl'
                    
                    packages.append(Package(
                        name=name,
                        version=version,
                        vendor=vendor_str,   # ej: 'openssl' (del CPE) o 'debian' (del SO)
                        product=product_str, # ej: 'openssl' (del CPE) o 'apt' (del nombre)
                        layer_id=layer_id_hash,
                        layer_index=layer_index
                    ))
                elif path and (path.startswith("/bin/") or path.startswith("/sbin/") or \
                              path.startswith("/usr/bin/") or path.startswith("/usr/sbin/") or \
                              path.startswith("/usr/local/bin/")):
                    
                    non_package_binaries.append(Binary(
                        path=path,
                        layer_id=layer_id_hash,
                        layer_index=layer_index
                    ))
        
        self._packages_cache = packages
        self._binaries_cache = non_package_binaries
        self._last_image_scanned = image_name

    def get_packages(self, image_name: str) -> List[Package]:
        self._run_scan_if_needed(image_name)
        return self._packages_cache or []

    def get_non_package_binaries(self, image_name: str) -> List[Binary]:
        self._run_scan_if_needed(image_name)
        return self._binaries_cache or []
        
    def get_os_info(self, image_name: str) -> Tuple[str, str]:
        self._run_scan_if_needed(image_name) 
        return (self._os_name_cache or "unknown", self._os_version_cache or "unknown")