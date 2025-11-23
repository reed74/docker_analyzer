import os
import json
import time
import math
import argparse
import requests
import psycopg2
import re
from datetime import datetime, timedelta, timezone
from tqdm import tqdm
from dotenv import load_dotenv

load_dotenv()

DB_CONFIG = {
    "dbname": os.getenv("DB_NAME"),
    "user": os.getenv("DB_USER"),
    "password": os.getenv("DB_PASS"),
    "host": os.getenv("DB_HOST"),
    "port": os.getenv("DB_PORT", "5432")
}

NVD_API_KEY = os.getenv("NVD_API_KEY")
BASE_URL = "https://services.nvd.nist.gov/rest/json/cves/2.0"
DOWNLOAD_DIR = "nvd_cache"

HEADERS = {
    "User-Agent": "Script-ETL-Python/1.2"
}
if NVD_API_KEY:
    HEADERS["apiKey"] = NVD_API_KEY
    DELAY = 0.6
else:
    DELAY = 6.0


def get_db_connection():
    return psycopg2.connect(**DB_CONFIG)

def reset_database(cur):
    """
    Vacia las tablas sin borrarlas (TRUNCATE).
    No necesita el archivo model_bd.sql.
    """
    print("\nATENCIÓN: Modo FULL detectado.")
    print("Limpiando datos existentes (TRUNCATE)...")
    
    # Tablas a limpiar. TRUNCATE
    tables = [
        "public.vulnerability_product_map", 
        "public.vulnerabilities", 
        "public.products", 

    ]
    
    try:
        for table in tables:

            cur.execute(f"TRUNCATE TABLE {table} RESTART IDENTITY CASCADE;")
        
        print("Tablas vaciadas correctamente. La estructura se mantiene.")
        
    except Exception as e:
        print(f"Error crítico al limpiar la base de datos: {e}")
        raise e

def parse_cpe_string(cpe_str):
    parts = cpe_str.split(':')
    while len(parts) < 13:
        parts.append(None)
    return {
        "part": parts[2] if parts[2] != '*' else None,
        "vendor": parts[3] if parts[3] != '*' else None,
        "product": parts[4] if parts[4] != '*' else None,
        "version": parts[5] if parts[5] != '*' else None,
        "update_info": parts[6] if parts[6] != '*' else None,
        "edition": parts[7] if parts[7] != '*' else None,
        "language": parts[8] if parts[8] != '*' else None,
        "sw_edition": parts[9] if parts[9] != '*' else None,
        "target_hw": parts[10] if parts[10] != '*' else None,
        "other": parts[11] if parts[11] != '*' else None
    }

def load_json_to_db(filepath, cur):
    with open(filepath, 'r', encoding='utf-8') as f:
        data = json.load(f)

    vulnerabilities = data.get('vulnerabilities', [])
    vuln_count = 0
    
    for item in vulnerabilities:
        cve_item = item['cve']
        cve_id = cve_item['id']

        descriptions = cve_item.get('descriptions', [])
        desc_text = next((d['value'] for d in descriptions if d['lang'] == 'en'), "")
        if not desc_text and descriptions: desc_text = descriptions[0]['value']

        cvss31, sev31, cvss40, sev40 = None, None, None, None
        metrics = cve_item.get('metrics', {})
        
        if 'cvssMetricV31' in metrics:
            d = metrics['cvssMetricV31'][0]['cvssData']
            cvss31, sev31 = d.get('baseScore'), d.get('baseSeverity')
        if 'cvssMetricV40' in metrics:
            d = metrics['cvssMetricV40'][0]['cvssData']
            cvss40, sev40 = d.get('baseScore'), d.get('baseSeverity')

        # Upsert Vulnerabilidad
        cur.execute("""
            INSERT INTO public.vulnerabilities 
            (cve_id, description, cvss_v31_score, cvss_v31_severity, cvss_v40_score, cvss_v40_severity)
            VALUES (%s, %s, %s, %s, %s, %s)
            ON CONFLICT (cve_id) DO UPDATE SET 
                description = EXCLUDED.description,
                cvss_v31_score = EXCLUDED.cvss_v31_score,
                cvss_v31_severity = EXCLUDED.cvss_v31_severity,
                cvss_v40_score = EXCLUDED.cvss_v40_score,
                cvss_v40_severity = EXCLUDED.cvss_v40_severity
            RETURNING id;
        """, (cve_id, desc_text, cvss31, sev31, cvss40, sev40))
        vuln_db_id = cur.fetchone()[0]
        vuln_count += 1

        configurations = cve_item.get('configurations', [])
        cpe_list = set()
        for config in configurations:
            for node in config.get('nodes', []):
                for match in node.get('cpeMatch', []):
                    if match.get('vulnerable'):
                        cpe_list.add(match['criteria'])
        
        for cpe_str in cpe_list:
            try:
                p = parse_cpe_string(cpe_str)
                cur.execute("""
                    INSERT INTO public.products 
                    (part, vendor, product, "version", update_info, edition, "language", sw_edition, target_hw, other)
                    VALUES (%(part)s, %(vendor)s, %(product)s, %(version)s, %(update_info)s, %(edition)s, %(language)s, %(sw_edition)s, %(target_hw)s, %(other)s)
                    ON CONFLICT (vendor, product, version, part, update_info, edition, language, sw_edition, target_hw, other) 
                    DO UPDATE SET part=EXCLUDED.part 
                    RETURNING id;
                """, p)
                prod_db_id = cur.fetchone()[0]
                
                cur.execute("""
                    INSERT INTO public.vulnerability_product_map (vulnerability_id, product_id)
                    VALUES (%s, %s) ON CONFLICT DO NOTHING;
                """, (vuln_db_id, prod_db_id))
            except Exception:
                continue
    return vuln_count


def download_nvd_data(incremental=False, days_back=1):
    target_dir = "nvd_cache_inc" if incremental else "nvd_cache"
    
    if not os.path.exists(target_dir):
        os.makedirs(target_dir)
        
    if incremental:
        for f in os.listdir(target_dir):
            os.remove(os.path.join(target_dir, f))

    params = {'resultsPerPage': 2000, 'startIndex': 0}

    if incremental:
        end_date = datetime.now(timezone.utc)
        start_date = end_date - timedelta(days=days_back)
        params['lastModStartDate'] = start_date.strftime('%Y-%m-%dT%H:%M:%S.000')
        params['lastModEndDate'] = end_date.strftime('%Y-%m-%dT%H:%M:%S.000')
        print(f"Modo INCREMENTAL: {start_date.strftime('%Y-%m-%d')} -> {end_date.strftime('%Y-%m-%d')}")
    else:
        print("Modo FULL LOAD: Historial completo.")

    try:
        check_params = params.copy()
        check_params['resultsPerPage'] = 1
        r = requests.get(BASE_URL, headers=HEADERS, params=check_params, timeout=30)
        r.raise_for_status()
        total_results = r.json().get('totalResults', 0)
        print(f"Registros detectados en NVD: {total_results}")
    except Exception as e:
        print(f"Error conectando a NVD: {e}")
        return target_dir, False

    if total_results == 0:
        print("No hay actualizaciones pendientes.")
        return target_dir, False

    for start_index in tqdm(range(0, total_results, 2000), desc="Descargando API"):
        filename = os.path.join(target_dir, f"nvd_chunk_{start_index}.json")
        
        # Lógica clave: Si existe y pesa > 1KB, NO descargar de nuevo
        if not incremental and os.path.exists(filename) and os.path.getsize(filename) > 1000:
            continue

        params['startIndex'] = start_index
        
        retries = 3
        success = False
        while not success and retries > 0:
            try:
                response = requests.get(BASE_URL, headers=HEADERS, params=params, timeout=60)
                if response.status_code == 200:
                    with open(filename, 'w', encoding='utf-8') as f:
                        json.dump(response.json(), f)
                    success = True
                else:
                    time.sleep(5)
                    retries -= 1
            except Exception:
                time.sleep(5)
                retries -= 1
        
        if not success:
            print(f"⚠️ Fallo en bloque {start_index}, se intentará continuar.")
        
        time.sleep(DELAY)
        
    return target_dir, True

def main():
    parser = argparse.ArgumentParser(description='ETL NVD CVE')
    parser.add_argument('--incremental', action='store_true', help='Carga incremental')
    parser.add_argument('--days', type=int, default=1, help='Días atrás')
    parser.add_argument('--full', action='store_true', help='Carga completa')
    
    args = parser.parse_args()

    if not (args.incremental or args.full):
        print("Uso: python carga_inicial.py --full  O  python carga_inicial.py --incremental")
        return

    # Descarga 
    download_dir, has_data = download_nvd_data(incremental=args.incremental, days_back=args.days)
    
    if not has_data and args.incremental:
        return

    # Procesamiento y Carga
    print("\nConectando a Base de Datos...")
    conn = get_db_connection()
    conn.autocommit = False
    cur = conn.cursor()
    
    try:

        if args.full:
            reset_database(cur)
            conn.commit() 

        files = sorted([f for f in os.listdir(download_dir) if f.endswith('.json')], 
                       key=lambda x: int(re.search(r'\d+', x).group()) if re.search(r'\d+', x) else 0)
        
        if not files:
            print("No hay archivos JSON para procesar.")
            return

        print(f"Procesando {len(files)} archivos desde {download_dir}...")
        
        for filename in tqdm(files, desc="Insertando en BD"):
            file_path = os.path.join(download_dir, filename)
            try:
                load_json_to_db(file_path, cur)
                conn.commit()
            except Exception as e:
                conn.rollback()
                print(f"Error en archivo {filename}: {e}")
                
        print("\nProceso finalizado correctamente.")
        
    except Exception as e:
        print(f"Error general: {e}")
        if conn: conn.rollback()
    finally:
        if cur: cur.close()
        if conn: conn.close()

if __name__ == "__main__":
    main()