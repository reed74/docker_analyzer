import sys
import os
import argparse
from dotenv import load_dotenv
from src.core.use_cases import ImageAnalyzerService
from src.adapters.syft_adapter import SyftAdapter 
from src.adapters.json_repository import JsonRepository
from src.adapters.postgres_cve_adapter import PostgresCveAdapter
from src.adapters.cyclonedx_adapter import CycloneDxAdapter
from src.adapters.summary_adapter import SummaryAdapter 
from src.core.domain import ImageAnalysisError

# Carga las variables del fichero .env
load_dotenv()

print(f"--- DEBUG .ENV: Buscando el fichero .env en la ruta: {os.path.abspath('.env')}")
if os.path.exists(".env"):
    print("--- DEBUG .ENV: ¡ÉXITO! Fichero .env encontrado y cargado.")
else:
    print("--- DEBUG .ENV: ¡FALLO! No se pudo encontrar el fichero .env.")


def main():
    
    # --- Parseo de argumentos ---
    parser = argparse.ArgumentParser(description="Analizador de vulnerabilidades de imágenes Docker.")
    parser.add_argument("image", help="Nombre de la imagen Docker (ej. 'nginx:1.10.3')")
    parser.add_argument("output_asset", help="Ruta del fichero de salida para los activos (ej. 'activos.json')")
    parser.add_argument("output_vuln", help="Ruta del fichero de salida para las vulnerabilidades (ej. 'vulns.json')")
    parser.add_argument(
        "--formato",
        choices=['custom', 'defectdojo'],
        default='custom',
        help="Formato de salida: 'custom' (dos ficheros JSON) o 'defectdojo' (un solo fichero CycloneDX en 'output_vuln')"
    )
    parser.add_argument(
        "--project_name",
        help="Nombre del proyecto en DefectDojo (usado con --formato defectdojo)"
    )
    # --- ¡NUEVO ARGUMENTO! ---
    parser.add_argument(
        "--summary_file",
        help="Ruta para un JSON de resumen de severidades (opcional, ej. 'resumen.json')"
    )
    
    args = parser.parse_args()

    try:
        # 1. Instanciar adaptadores
        image_provider = SyftAdapter() 
        cve_repo = PostgresCveAdapter()
        
        # 2. Ejecutar el caso de uso
        analyzer_service = ImageAnalyzerService(
            data_provider=image_provider,
            cve_repo=cve_repo 
        )
        
        asset_report, vuln_report = analyzer_service.analyze_image(args.image)
        
        # 4. Lógica de guardado principal
        if args.formato == 'defectdojo':
            print(f"\nGenerando informe en formato CycloneDX (para DefectDojo)...")
            dx_repo = CycloneDxAdapter()
            dx_repo.save(asset_report, vuln_report, args.output_vuln, args.project_name)
            print(f"Reporte CycloneDX (para DefectDojo) guardado en {args.output_vuln}")
        
        else: # 'custom' es el default
            print(f"\nGenerando informes en formato JSON personalizado...")
            json_repo = JsonRepository()
            json_repo.save_asset_report(asset_report, args.output_asset)
            json_repo.save_vulnerability_report(vuln_report, args.output_vuln)
            print(f"Reporte de activos guardado en {args.output_asset}")
            print(f"Reporte de vulnerabilidades guardado en {args.output_vuln}")
        
        # 5. Guardar resumen si se ha pedido 
        if args.summary_file:
            print(f"Generando informe de resumen...")
            summary_repo = SummaryAdapter()
            summary_repo.save(vuln_report, args.summary_file)
            print(f"Reporte de resumen guardado en {args.summary_file}")
        
        print("\n Análisis completado con éxito.")

    except ImageAnalysisError as e:
        print(f"\n ERROR DE ANÁLISIS: No se pudo completar la operación.")
        print(f"   Motivo: {e}")
        sys.exit(1)
    except Exception as e:
        print(f"\n ERROR INESPERADO: Ha ocurrido un error crítico.")
        print(f"   Detalle: {e}")
        sys.exit(1)

if __name__ == "__main__":
    main()