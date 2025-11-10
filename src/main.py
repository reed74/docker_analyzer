import sys
import os
from dotenv import load_dotenv
from src.core.use_cases import ImageAnalyzerService
from src.adapters.syft_adapter import SyftAdapter 
from src.adapters.json_repository import JsonRepository
from src.adapters.postgres_cve_adapter import PostgresCveAdapter
from src.core.domain import ImageAnalysisError  # <-- 1. Importar la excepción

# Carga las variables del fichero .env al entorno de ejecución
load_dotenv()
print(f"--- DEBUG .ENV: Buscando el fichero .env en la ruta: {os.path.abspath('.env')}")
if os.path.exists(".env"):
    print("--- DEBUG .ENV: ¡ÉXITO! Fichero .env encontrado y cargado.")
else:
    print("--- DEBUG .ENV: ¡FALLO! No se pudo encontrar el fichero .env.")


def main():
    
    if len(sys.argv) < 4:
        print("\nUso: python3 -m src.main <nombre_imagen> <salida_activos.json> <salida_vulns.json>")
        print("Ejemplo: python3 -m src.main nginx:1.10.3 activos.json vulnerabilidades.json")
        print("(La configuración de la BD se lee desde el fichero .env)")
        sys.exit(1)
        
    image_name = sys.argv[1]
    asset_output_file = sys.argv[2]
    vuln_output_file = sys.argv[3] 

    # --- ¡NUEVO BLOQUE TRY...EXCEPT! ---
    try:
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
        
        print("\n✅ Análisis completado con éxito.")

    except ImageAnalysisError as e:
        # 4. Capturar el error de nuestro adaptador
        print(f"\n❌ ERROR DE ANÁLISIS: No se pudo completar la operación.")
        print(f"   Motivo: {e}")
        sys.exit(1) # Salir con código de error
    except Exception as e:
        # 5. Capturar cualquier otro error inesperado
        print(f"\n❌ ERROR INESPERADO: Ha ocurrido un error crítico.")
        print(f"   Detalle: {e}")
        sys.exit(1)
    # --- FIN DEL BLOQUE ---

if __name__ == "__main__":
    main()