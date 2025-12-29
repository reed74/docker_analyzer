import os
import json
import requests
import zipfile
import psycopg2
import io
import shutil
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

# lenguajes y dependencias a procesar
ECOSYSTEMS = [
    {
        "name": "Maven",
        "url": "https://osv-vulnerabilities.storage.googleapis.com/Maven/all.zip",
        "target_hw": "maven",
        "type": "java"
    },
    {
        "name": "PyPI",
        "url": "https://osv-vulnerabilities.storage.googleapis.com/PyPI/all.zip",
        "target_hw": "pypi",
        "type": "python"
    },
    {
        "name": "Go",
        "url": "https://osv-vulnerabilities.storage.googleapis.com/Go/all.zip",
        "target_hw": "go",
        "type": "go"
    },
    {
        "name": "npm",
        "url": "https://osv-vulnerabilities.storage.googleapis.com/npm/all.zip",
        "target_hw": "npm",   # Cubre JavaScript y TypeScript
        "type": "npm"
    },
    {
        "name": "NuGet",
        "url": "https://osv-vulnerabilities.storage.googleapis.com/NuGet/all.zip",
        "target_hw": "nuget", # Cubre .NET (C#, F#, VB.NET)
        "type": "nuget"
    },
    {
        "name": "Packagist",
        "url": "https://osv-vulnerabilities.storage.googleapis.com/Packagist/all.zip",
        "target_hw": "packagist", 
        "type": "php"
    },
    {
        "name": "crates.io",
        "url": "https://osv-vulnerabilities.storage.googleapis.com/crates.io/all.zip",
        "target_hw": "crates", 
        "type": "rust"
    }
]

def get_db_connection():
    return psycopg2.connect(**DB_CONFIG)

def download_and_extract(ecosystem_conf):
    """Descarga y extrae el ZIP específico del ecosistema"""
    print(f"\n Descargando DB de {ecosystem_conf['name']}...")
    try:
        r = requests.get(ecosystem_conf['url'], stream=True)
        z = zipfile.ZipFile(io.BytesIO(r.content))
        
        extract_path = f"osv_cache_{ecosystem_conf['name'].lower().replace('.', '_')}"
        if os.path.exists(extract_path):
            shutil.rmtree(extract_path) 
        os.makedirs(extract_path)
        
        z.extractall(extract_path)
        return extract_path
    except Exception as e:
        print(f" Error descargando {ecosystem_conf['name']}: {e}")
        return None

def parse_package_identity(ecosystem_type, full_name):
    """
    Normaliza el nombre del paquete según el lenguaje para llenar Vendor/Product de forma inteligente.
    Retorna: (vendor, product)
    """
    vendor = full_name
    product = full_name

    if ecosystem_type == 'java':
        # Maven: "org.apache:commons-lang3" -> Vendor: org.apache, Product: commons-lang3
        if ':' in full_name:
            vendor, product = full_name.split(':', 1)

    elif ecosystem_type == 'npm':
        # npm: Puede ser global ("react") o scoped ("@angular/core")
        if full_name.startswith('@') and '/' in full_name:
            # Vendor: @angular, Product: core
            vendor, product = full_name.split('/', 1)
        else:
            # Vendor: react, Product: react
            vendor = full_name
            product = full_name

    elif ecosystem_type == 'php':
        # Packagist: Siempre es "vendor/package" (ej: "laravel/framework")
        if '/' in full_name:
            vendor, product = full_name.split('/', 1)

    elif ecosystem_type == 'go':
        # Go: Usamos el path completo para evitar colisiones
        # ej: "github.com/gin-gonic/gin"
        pass 

    elif ecosystem_type == 'nuget':
        # .NET: Suelen usar puntos (Microsoft.AspNetCore.Mvc).
        # Es mejor guardar el nombre completo para exactitud.
        pass

    elif ecosystem_type == 'rust':
        # Crates.io: Nombre único simple (ej: "tokio")
        pass

    # Fallback y Python
    return vendor, product

def get_cve_id_db(cur, cve_string):
    cur.execute("SELECT id FROM public.vulnerabilities WHERE cve_id = %s", (cve_string,))
    res = cur.fetchone()
    return res[0] if res else None

def ensure_product_exists(cur, vendor, product, version, target_hw):
    """Inserta CPE sintético marcado con el ecosistema en target_hw"""
    product_data = {
        "part": "a",
        "vendor": vendor,
        "product": product,
        "version": version,
        "update_info": None,
        "edition": None,
        "language": None,
        "sw_edition": None,
        "target_hw": target_hw, 
        "other": None
    }

    query = """
        INSERT INTO public.products 
        (part, vendor, product, "version", update_info, edition, "language", sw_edition, target_hw, other)
        VALUES (%(part)s, %(vendor)s, %(product)s, %(version)s, %(update_info)s, %(edition)s, %(language)s, %(sw_edition)s, %(target_hw)s, %(other)s)
        ON CONFLICT (vendor, product, version, part, update_info, edition, language, sw_edition, target_hw, other) 
        DO UPDATE SET part=EXCLUDED.part
        RETURNING id;
    """
    cur.execute(query, product_data)
    return cur.fetchone()[0]

def link_vuln_prod(cur, vuln_id, prod_id):
    cur.execute("""
        INSERT INTO public.vulnerability_product_map (vulnerability_id, product_id)
        VALUES (%s, %s)
        ON CONFLICT DO NOTHING;
    """, (vuln_id, prod_id))

def process_ecosystem(folder_path, ecosystem_conf):
    conn = get_db_connection()
    conn.autocommit = False 
    cur = conn.cursor()

    files = [f for f in os.listdir(folder_path) if f.endswith('.json')]
    print(f"🔄 Procesando {len(files)} vulns de {ecosystem_conf['name']}...")

    cve_db_cache = {} 

    for filename in tqdm(files, desc=f"Cargando {ecosystem_conf['name']}"):
        try:
            with open(os.path.join(folder_path, filename), 'r', encoding='utf-8') as f:
                data = json.load(f)

            # 1. Resolver CVE (Buscamos ID principal o aliases)
            cve_code = None
            if data['id'].startswith('CVE-'):
                cve_code = data['id']
            elif 'aliases' in data:
                for alias in data['aliases']:
                    if alias.startswith('CVE-'):
                        cve_code = alias
                        break
            
            if not cve_code:
                continue

            if cve_code in cve_db_cache:
                vuln_db_id = cve_db_cache[cve_code]
            else:
                vuln_db_id = get_cve_id_db(cur, cve_code)
                if not vuln_db_id:
                    continue
                cve_db_cache[cve_code] = vuln_db_id

            
            for affected in data.get('affected', []):
                package = affected.get('package', {})
                
                
                if package.get('ecosystem') == ecosystem_conf['name']:
                    full_name = package.get('name', '')
                    
                    
                    vendor, product = parse_package_identity(ecosystem_conf['type'], full_name)

                    if 'versions' in affected:
                        for ver in affected['versions']:
                            prod_id = ensure_product_exists(
                                cur, 
                                vendor, 
                                product, 
                                ver, 
                                ecosystem_conf['target_hw']
                            )
                            link_vuln_prod(cur, vuln_db_id, prod_id)

            conn.commit()
            
        except Exception as e:
            conn.rollback()
            

    cur.close()
    conn.close()
    print(f" {ecosystem_conf['name']} completado.")


def main():
    print(" Iniciando carga multi-lenguaje OSV -> BD")
    
    for eco in ECOSYSTEMS:
        folder = download_and_extract(eco)
        if folder:
            process_ecosystem(folder, eco)
            # Descomenta la siguiente línea si quieres borrar los archivos tras procesarlos
            # shutil.rmtree(folder)
            
    print("\n Proceso global finalizado.")

if __name__ == "__main__":
    main()