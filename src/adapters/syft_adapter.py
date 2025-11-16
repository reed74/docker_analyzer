import subprocess
import json
import re
from typing import List, Dict, Any, Optional, Tuple

from src.core.ports import ImageDataProvider
from src.core.domain import Package, Binary, ImageAnalysisError # Importa el Error

def _parse_cpe(cpe_string: str) -> Tuple[Optional[str], Optional[str]]:
    """
    Función helper para extraer (vendor, product) de una cadena CPE 2.3.
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

    def _ensure_image_is_local(self, image_name: str):
        """
        Comprueba si una imagen existe localmente. Si no, intenta descargarla.
        Lanza ImageAnalysisError si la descarga falla.
        """
        try:
            # 1. Comprueba si la imagen existe localmente
            # --- ¡AQUÍ ESTÁ LA CORRECCIÓN! ---
            # Hemos quitado 'capture_output=True' para evitar el conflicto
            subprocess.run(
                ["docker", "image", "inspect", image_name],
                check=True, text=True,
                stdout=subprocess.DEVNULL, 
                stderr=subprocess.DEVNULL
            )
            # --- FIN DE LA CORRECCIÓN ---
            print(f"Imagen '{image_name}' encontrada localmente.")
            return
            
        except subprocess.CalledProcessError:
            # 2. La imagen no está local. Intentamos descargarla.
            print(f"Imagen '{image_name}' no encontrada localmente. Intentando descargar (docker pull)...")
            try:
                # Esta llamada (docker pull) SÍ usa capture_output y está bien
                pull_result = subprocess.run(
                    ["docker", "pull", image_name],
                    check=True, capture_output=True, text=True
                )
                print(f"Descarga de '{image_name}' completada.")
            except subprocess.CalledProcessError as pull_error:
                # 3. La descarga ha fallado
                print(f"ERROR: No se pudo descargar la imagen '{image_name}'.")
                print(f"Detalle: {pull_error.stderr}")
                raise ImageAnalysisError(f"La imagen '{image_name}' no se pudo encontrar ni descargar.") from pull_error

    def _get_syft_json(self, image_name: str) -> Dict[str, Any]:
        """
        Ejecuta syft y devuelve la salida JSON parseada.
        """
        print(f"Ejecutando syft para {image_name}... (esto puede tardar un momento)")
        try:
            cmd = ["syft", "scan", f"docker:{image_name}", "-o", "json", "-s", "all-layers"]
            
            result = subprocess.run(
                cmd,
                capture_output=True,
                text=True,
                check=True,
                encoding="utf-8"
            )
            
            if not result.stdout:
                raise ImageAnalysisError("Syft se ejecutó pero no devolvió ninguna salida (stdout).")

            return json.loads(result.stdout)
        
        except FileNotFoundError:
            print("Error: 'syft' no se encuentra. ¿Está instalado y en el PATH?")
            raise
        except subprocess.CalledProcessError as e:
            print(f"Error inesperado al ejecutar syft: {e.stderr}")
            raise ImageAnalysisError(f"Fallo al analizar la imagen: {image_name}") from e
        except json.JSONDecodeError as e:
            print(f"Error: Syft devolvió un JSON inválido. Error: {e}")
            raise ImageAnalysisError(f"Syft devolvió datos corruptos para: {image_name}") from e
        except Exception as e:
            print(f"Un error inesperado ocurrió en _get_syft_json: {e}")
            raise ImageAnalysisError(f"Error inesperado: {e}") from e

    def _run_scan_if_needed(self, image_name: str):
        """
        Función interna que ejecuta el análisis de syft y procesa los datos,
        pero solo si no se ha hecho ya para esta imagen.
        """
        if self._last_image_scanned == image_name:
            return

        print(f"Analizando datos de Syft para {image_name}...")
        
        # 1. Aseguramos que la imagen exista ANTES de llamar a syft
        self._ensure_image_is_local(image_name)
        
        # 2. Ahora podemos llamar a syft con seguridad
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
                purl = artifact.get("purl", "") 

                if not (name and version and locations):
                    continue  

                location = locations[0]
                path = location.get("path")
                layer_id_hash = location.get("layerID", "unknown")
                layer_index = layer_hash_to_index_map.get(layer_id_hash, -1)

                if pkg_type in os_package_types:
                    
                    vendor_str, product_str = None, None
                    if cpe_list:
                        vendor_str, product_str = _parse_cpe(cpe_list[0])
                    
                    if not vendor_str:
                        vendor_str = os_name.lower().split()[0]
                    if not product_str:
                        product_str = name 

                    packages.append(Package(
                        name=name,
                        version=version,
                        vendor=vendor_str,
                        product=product_str,
                        purl=purl,
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