-- 1. Creación de la tabla temporal --

            CREATE TEMPORARY TABLE input_packages (
                product TEXT,
                version TEXT
            ) ON COMMIT DROP;
        

-- 2. Inserción de 16 paquetes únicos --
INSERT INTO input_packages (product, version) VALUES ('apk-tools', '2.14.9');
INSERT INTO input_packages (product, version) VALUES ('alpine-keys', '2.5');
INSERT INTO input_packages (product, version) VALUES ('libssl3', '3.5.4');
INSERT INTO input_packages (product, version) VALUES ('scanelf', '1.3.8');
INSERT INTO input_packages (product, version) VALUES ('alpine-baselayout-data', '3.7.0');
INSERT INTO input_packages (product, version) VALUES ('zlib', '1.3.1');
INSERT INTO input_packages (product, version) VALUES ('musl-utils', '1.2.5');
INSERT INTO input_packages (product, version) VALUES ('ssl_client', '1.37.0');
INSERT INTO input_packages (product, version) VALUES ('libapk2', '2.14.9');
INSERT INTO input_packages (product, version) VALUES ('alpine-baselayout', '3.7.0');
INSERT INTO input_packages (product, version) VALUES ('alpine-release', '3.22.2');
INSERT INTO input_packages (product, version) VALUES ('libcrypto3', '3.5.4');
INSERT INTO input_packages (product, version) VALUES ('busybox-binsh', '1.37.0');
INSERT INTO input_packages (product, version) VALUES ('musl', '1.2.5');
INSERT INTO input_packages (product, version) VALUES ('busybox', '1.37.0');
INSERT INTO input_packages (product, version) VALUES ('ca-certificates-bundle', '20250911');

-- 3. Consulta final (JOIN) --

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
        
