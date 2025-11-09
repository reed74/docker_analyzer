import sys
import os
from dotenv import load_dotenv
from src.core.use_cases import ImageAnalyzerService
from src.adapters.syft_adapter import SyftAdapter 
from src.adapters.json_repository import JsonRepository
from src.adapters.postgres_cve_adapter import PostgresCveAdapter

load_dotenv()
print(f"--- DEBUG .ENV: Buscando el fichero .env en la ruta: {os.path.abspath('.env')}")
if os.path.exists(".env"):
    print("--- DEBUG .ENV: ¡ÉXITO! Fichero .env encontrado y cargado.")
else:
    print("--- DEBUG .ENV: ¡FALLO! No se pudo encontrar el fichero .env.")


def main():
    
    # Ahora necesitamos 3 argumentos
    if len(sys.argv) < 4:
        print("\nUso: python3 -m src.main <nombre_imagen> <salida_activos.json> <salida_vulns.json>")
        print("Ejemplo: python3 -m src.main nginx:1.10.3 activos.json vulnerabilidades.json")
        print("(La configuración de la BD se lee desde el fichero .env)")
        sys.exit(1)
        
    image_name = sys.argv[1]
    asset_output_file = sys.argv[2]   # <-- 1er fichero de salida
    vuln_output_file = sys.argv[3]    # <-- 2º fichero de salida
 

    # 1. Instanciar los adaptadores de infraestructura
    image_provider = SyftAdapter() 
    json_repo = JsonRepository()
    cve_repo = PostgresCveAdapter()
    
    # 2. Inyectar los adaptadores en el servicio del núcleo
    analyzer_service = ImageAnalyzerService(
        data_provider=image_provider,
        json_repo=json_repo,
        cve_repo=cve_repo 
    )
    
    # 3. Ejecutar el caso de uso con las nuevas rutas
    analyzer_service.analyze_image(image_name, asset_output_file, vuln_output_file)

if __name__ == "__main__":
    main()