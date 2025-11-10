Analizador de Vulnerabilidades Docker

Este proyecto es una herramienta de análisis de seguridad en Python que escanea imágenes Docker para extraer un inventario de activos (SBOM) y compararlo contra una base de datos de vulnerabilidades personalizada (basada en el modelo NIST/CPE).

Utiliza una Arquitectura Hexagonal (Puertos y Adaptadores) para separar la lógica de negocio principal de las herramientas de infraestructura (como syft y la base de datos PostgreSQL).

Características Principales

    Análisis de Imágenes Docker: Extrae información de cualquier imagen Docker local.

    Generación de SBOM: Utiliza syft para catalogar el sistema operativo, los paquetes del sistema (.deb, .apk, etc.) y los binarios (ej. Go).

    Detección de Vulnerabilidades Personalizada: Compara el inventario de paquetes contra una base de datos PostgreSQL propia (compatible con CPE) para encontrar CVEs.

    Separación de Informes: Genera dos ficheros JSON distintos:

        activos.json: Un inventario (SBOM) de todo lo encontrado en la imagen.

        vulnerabilidades.json: Un informe de las vulnerabilidades encontradas, agrupadas por paquete y versión.


Arquitectura

El proyecto sigue un diseño de Arquitectura Hexagonal para aislar la lógica central de las herramientas externas.

    Núcleo (Core):

        domain.py: Define los modelos de datos (ej. Package, Vulnerability).

        ports.py: Define las interfaces (ej. ImageDataProvider, CveRepository).

        use_cases.py: Orquesta la lógica principal (ej. ImageAnalyzerService).

    Adaptadores (Adapters):

        syft_adapter.py: Implementa ImageDataProvider usando la herramienta syft.

        postgres_cve_adapter.py: Implementa CveRepository conectándose a una BD PostgreSQL.

        json_repository.py: Implementa AnalysisRepository para guardar los informes en JSON.

        main.py: El punto de entrada que "conecta" los adaptadores al núcleo.

Empezar

Prerrequisitos

Antes de empezar, asegúrate de tener todo esto instalado en tu sistema:

    Python 3.10+

    Docker: Debe estar instalado y en ejecución.

    Syft: La herramienta de syft debe estar instalada globalmente.
    Bash

curl -sSfL https://raw.githubusercontent.com/anchore/syft/main/install.sh | sudo sh -s -- -b /usr/local/bin

PostgreSQL: Una base de datos PostgreSQL en ejecución y accesible.

Librerías de desarrollo de Python y PostgreSQL (necesarias para compilar el conector psycopg):
Bash

    # Para sistemas basados en Debian/Ubuntu
    sudo apt-get install python3-dev libpq-dev

Instalación del Proyecto

    Clona el repositorio:
    Bash

git clone <url-de-tu-repositorio>
cd docker_analyzer

Crea y activa el entorno virtual (venv):
Bash

python3 -m venv venv
source venv/bin/activate

Instala las dependencias de Python:
Bash

pip install python-dotenv psycopg

Configura tu Base de Datos:

    Carga el esquema de tu BD (el fichero vulnerabilities_251110.sql o el que corresponda por fecha) en tu instancia de PostgreSQL.


Crea tu fichero de entorno: Crea un fichero llamado .env en la raíz del proyecto (docker_analyzer/.env) con tus credenciales.

Plantilla .env:
Ini, TOML

    DB_HOST=localhost
    DB_PORT=5432
    DB_NAME=vulnerabilities
    DB_USER=tu_usuario
    DB_PASS=tu_contraseña_secreta

    (Importante) Añade .env a tu .gitignore para no subir tus contraseñas a Git.

Uso

Para ejecutar un análisis, utiliza el script main.py desde la raíz del proyecto. Debes pasarle tres argumentos:

    El nombre de la imagen Docker (ej. nginx:1.10.3).

    El nombre del fichero de salida para los activos (SBOM).

    El nombre del fichero de salida para las vulnerabilidades.

Ejemplo de Ejecución

Bash

# Asegúrate de que tu venv esté activo
source venv/bin/activate

# Ejecuta el análisis en la imagen Nginx antigua
python3 -m src.main nobmre_imagen nombre_salida.json vulnerabilidades_nobre_imagen.json

Salida en la terminal:

--- DEBUG .ENV: Buscando el fichero .env en la ruta: /.../docker_analyzer/.env
--- DEBUG .ENV: ¡ÉXITO! Fichero .env encontrado y cargado.
Iniciando análisis de nginx:1.10.3...
Analizando datos de Syft para nginx:1.10.3...
Ejecutando syft para nginx:1.10.3... (esto puede tardar un momento)
Encontrados 140 paquetes.
Encontrados 0 binarios sin paquete.
Sistema Operativo detectado: Debian GNU/Linux:8 (jessie)

--- DEBUG: Preparando datos de paquetes para la BD (muestra de 5):
  -> Buscando: (v='debian', p='apt', ver='1.0.9.8.4')
  -> Buscando: (v='debian', p='base-files', ver='8')
  ...
--- DEBUG: Total de 140 paquetes, 140 únicos para consultar. ---

Encontradas 115 vulnerabilidades de paquetes en tu BD.

--- DEBUG: Buscando vulnerabilidades para el SO: (v='debian', p='debian', ver='8') ---
Encontradas 0 vulnerabilidades del SO en tu BD.
Reporte de activos guardado en activos_nginx.json
Reporte de vulnerabilidades guardado en vulnerabilidades_nginx.json
