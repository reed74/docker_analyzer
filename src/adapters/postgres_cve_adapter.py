import psycopg
import os
import re
from typing import List
from psycopg.rows import dict_row 

from src.core.ports import CveRepository
from src.core.domain import Package, Vulnerability

class PostgresCveAdapter(CveRepository):
    
    def __init__(self):
        try:
            host = os.environ.get("DB_HOST", "localhost")
            port = os.environ.get("DB_PORT", "5432")
            dbname = os.environ.get("DB_NAME")
            user = os.environ.get("DB_USER")
            password = os.environ.get("DB_PASS")
            
            if not all([dbname, user, password]):
                print("Error: Faltan variables de entorno (DB_NAME, DB_USER, DB_PASS) en el fichero .env")
                self.db_conn_string = None
            else:
                self.db_conn_string = f"postgresql://{user}:{password}@{host}:{port}/{dbname}"
        
        except Exception as e:
            print(f"Error al construir la cadena de conexión: {e}")
            self.db_conn_string = None
            
    def _write_debug_sql_file(self, create_query: str, insert_template: str, select_query: str, data: List[tuple]):
        """
        Escribe la secuencia completa de consultas SQL en un fichero de log
        para la depuración manual.
        """
        log_filename = "debug_queries.sql"
        try:
            with open(log_filename, 'w', encoding='utf-8') as f:
                print(f"\n--- DEBUG SQL: Escribiendo log de SQL en: {os.path.abspath(log_filename)} ---")
                
                f.write("-- 1. Creación de la tabla temporal --\n")
                f.write(create_query)
                f.write("\n\n")
                
                f.write(f"-- 2. Inserción de {len(data)} paquetes únicos --\n")
                for product, version in data: # <-- ¡Solo product y version!
                    safe_product = product.replace("'", "''")
                    safe_version = version.replace("'", "''")
                    f.write(f"INSERT INTO input_packages (product, version) VALUES ('{safe_product}', '{safe_version}');\n")
                
                f.write("\n-- 3. Consulta final (JOIN) --\n")
                f.write(select_query)
                f.write("\n")
            
            print("--- DEBUG SQL: Log de SQL escrito con éxito. ---")
        
        except IOError as e:
            print(f"--- DEBUG SQL: ¡Error! No se pudo escribir el fichero de log: {e} ---")

    def find_package_vulnerabilities(self, packages: List[Package]) -> List[Vulnerability]:
        """
        Busca vulnerabilidades para la lista de paquetes de software.
        """
        if not packages:
            return []
        
        if not self.db_conn_string:
            print("No hay cadena de conexión a la BD, saltando búsqueda de CVEs de paquetes.")
            return []

        # 1. Preparar los datos (solo product y version)
        package_tuples = []
        print("\n--- DEBUG: Preparando datos de paquetes para la BD (muestra de 5):")
        
        for pkg in packages:
            # Limpia la versión: '1.0.1t-1+deb8u6' -> '1.0.1t'
            cleaned_version = re.split(r'[-+]', pkg.version, maxsplit=1)[0]
            
            if len(package_tuples) < 5: 
                 # Ahora solo nos importa 'product' y 'version'
                 print(f"  -> Buscando: (p='{pkg.product}', ver='{cleaned_version}')")
            
            package_tuples.append((pkg.product, cleaned_version)) # <-- ¡Solo product y version!
        
        unique_packages = list(set(package_tuples))
        print(f"--- DEBUG: Total de {len(packages)} paquetes, {len(unique_packages)} únicos para consultar. ---\n")
        
        
        # --- 2. Consultas SQL actualizadas  ---
        create_table_query = """
            CREATE TEMPORARY TABLE input_packages (
                product TEXT,
                version TEXT
            ) ON COMMIT DROP;
        """
        
        insert_query_template = "INSERT INTO input_packages (product, version) VALUES (%s, %s)"

        select_query = """
            SELECT 
                p.product, p.version, v.cve_id, v.cvss_v31_severity
            FROM 
                public.vulnerabilities AS v
            JOIN 
                public.vulnerability_product_map AS vpm ON v.id = vpm.vulnerability_id
            JOIN 
                public.products AS p ON vpm.product_id = p.id
            JOIN 
                input_packages AS i 
            ON 
                p.product = i.product 
                AND p.version = i.version;
        """
     
        # 3. Escribir el fichero de log 
        self._write_debug_sql_file(create_table_query, insert_query_template, select_query, unique_packages)

        
        # 4. Ejecución normal de la consulta
        found_vulns = []
        try:
            with psycopg.connect(self.db_conn_string, row_factory=dict_row) as conn:
                with conn.cursor() as cursor:
                    
                    cursor.execute(create_table_query) 
                    cursor.executemany(insert_query_template, unique_packages)
                    cursor.execute(select_query)

                    for row in cursor.fetchall():
                        found_vulns.append(
                            Vulnerability(
                                package_name=row["product"],
                                package_version=row["version"], 
                                cve_id=row["cve_id"],
                                severity=row["cvss_v31_severity"]
                            )
                        )
                        
        except psycopg.Error as e:
            print(f"Error al consultar la BD de CVEs de paquetes: {e}")
            return []
            
        return found_vulns

    def find_os_vulnerabilities(self, os_name: str, os_version: str) -> List[Vulnerability]:
        """
        Busca vulnerabilidades asociadas directamente al sistema operativo.
        """
        if not self.db_conn_string or os_name == "unknown":
            return []
        
        vendor_str = os_name.lower().split()[0] # 'debian'
        product_str = vendor_str # 'debian'
        version_str = os_version.split()[0] # '8'

        print(f"\n--- DEBUG: Buscando vulnerabilidades para el SO: (v='{vendor_str}', p='{product_str}', ver='{version_str}') ---")

        query = """
            SELECT 
                p.product, p.version, v.cve_id, v.cvss_v31_severity
            FROM 
                public.vulnerabilities AS v
            JOIN 
                public.vulnerability_product_map AS vpm ON v.id = vpm.vulnerability_id
            JOIN 
                public.products AS p ON vpm.product_id = p.id
            WHERE 
                p.vendor = %s
                AND p.product = %s
                AND p.version = %s;
        """

        log_filename = "debug_queries_os.sql"
        try:
            with open(log_filename, 'w', encoding='utf-8') as f:
                print(f"--- DEBUG SQL: Escribiendo log de SO en: {os.path.abspath(log_filename)} ---")
                safe_vendor = vendor_str.replace("'", "''")
                safe_product = product_str.replace("'", "''")
                safe_version = version_str.replace("'", "''")
                
                debug_query_sql = query.replace("%s", f"'{safe_vendor}'", 1)
                debug_query_sql = debug_query_sql.replace("%s", f"'{safe_product}'", 1)
                debug_query_sql = debug_query_sql.replace("%s", f"'{safe_version}'", 1)
                f.write(debug_query_sql)
            print("--- DEBUG SQL: Log de SO escrito con éxito. ---")
        except IOError as e:
            print(f"--- DEBUG SQL: ¡Error! No se pudo escribir el fichero de log de SO: {e} ---")


        found_vulns = []
        try:
            with psycopg.connect(self.db_conn_string, row_factory=dict_row) as conn:
                with conn.cursor() as cursor:
                    cursor.execute(query, (vendor_str, product_str, version_str))
                    for row in cursor.fetchall():
                        found_vulns.append(
                            Vulnerability(
                                package_name=row["product"],
                                package_version=row["version"], 
                                cve_id=row["cve_id"],
                                severity=row["cvss_v31_severity"]
                            )
                        )
        except psycopg.Error as e:
            print(f"Error al consultar la BD de CVEs de SO: {e}")
            return []
            
        return found_vulns