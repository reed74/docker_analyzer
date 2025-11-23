-- DROP SCHEMA public;

CREATE SCHEMA public AUTHORIZATION pg_database_owner;

-- DROP SEQUENCE public.products_id_seq;

CREATE SEQUENCE public.products_id_seq
	INCREMENT BY 1
	MINVALUE 1
	MAXVALUE 2147483647
	START 1
	CACHE 1
	NO CYCLE;
-- DROP SEQUENCE public.vulnerabilities_id_seq;

CREATE SEQUENCE public.vulnerabilities_id_seq
	INCREMENT BY 1
	MINVALUE 1
	MAXVALUE 2147483647
	START 1
	CACHE 1
	NO CYCLE;-- public.package_aliases definition

-- Drop table

-- DROP TABLE public.package_aliases;

CREATE TABLE public.package_aliases (
	alias_name text NOT NULL,
	canonical_name text NOT NULL,
	CONSTRAINT package_aliases_pkey PRIMARY KEY (alias_name)
);
CREATE INDEX idx_canonical_name ON public.package_aliases USING btree (canonical_name);


-- public.products definition

-- Drop table

-- DROP TABLE public.products;

CREATE TABLE public.products (
	id serial4 NOT NULL,
	part text NULL,
	vendor text NULL,
	product text NULL,
	"version" text NULL,
	update_info text NULL,
	edition text NULL,
	"language" text NULL,
	sw_edition text NULL,
	target_hw text NULL,
	other text NULL,
	CONSTRAINT products_pkey PRIMARY KEY (id),
	CONSTRAINT products_vendor_product_version_part_update_info_edition_la_key UNIQUE (vendor, product, version, part, update_info, edition, language, sw_edition, target_hw, other)
);
CREATE INDEX idx_products_lookup ON public.products USING btree (vendor, product, version);


-- public.vulnerabilities definition

-- Drop table

-- DROP TABLE public.vulnerabilities;

CREATE TABLE public.vulnerabilities (
	id serial4 NOT NULL,
	cve_id text NOT NULL,
	description text NULL,
	cvss_v31_score float4 NULL,
	cvss_v31_severity text NULL,
	cvss_v40_score float4 NULL,
	cvss_v40_severity text NULL,
	CONSTRAINT vulnerabilities_cve_id_key UNIQUE (cve_id),
	CONSTRAINT vulnerabilities_pkey PRIMARY KEY (id)
);


-- public.vulnerability_product_map definition

-- Drop table

-- DROP TABLE public.vulnerability_product_map;

CREATE TABLE public.vulnerability_product_map (
	vulnerability_id int4 NOT NULL,
	product_id int4 NOT NULL,
	CONSTRAINT vulnerability_product_map_pkey PRIMARY KEY (vulnerability_id, product_id),
	CONSTRAINT vulnerability_product_map_product_id_fkey FOREIGN KEY (product_id) REFERENCES public.products(id) ON DELETE CASCADE,
	CONSTRAINT vulnerability_product_map_vulnerability_id_fkey FOREIGN KEY (vulnerability_id) REFERENCES public.vulnerabilities(id) ON DELETE CASCADE
);
CREATE INDEX idx_map_prod_id ON public.vulnerability_product_map USING btree (product_id);
CREATE INDEX idx_map_vuln_id ON public.vulnerability_product_map USING btree (vulnerability_id);


