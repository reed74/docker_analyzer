
            SELECT 
                p.product, p.version, v.cve_id, v.cvss_v31_severity
            FROM 
                public.vulnerabilities AS v
            JOIN 
                public.vulnerability_product_map AS vpm ON v.id = vpm.vulnerability_id
            JOIN 
                public.products AS p ON vpm.product_id = p.id
            WHERE 
                p.vendor = 'debian'
                AND p.product = 'debian'
                AND p.version = '8';
        