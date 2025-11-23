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

Aquí tienes una versión completamente actualizada que refleja todo lo que hemos implementado.

Analizador Hexagonal de Vulnerabilidades Docker

Este proyecto es una herramienta de análisis de seguridad en Python que escanea imágenes Docker para extraer un inventario de activos (SBOM) y compararlo contra una base de datos de vulnerabilidades PostgreSQL personalizada (basada en el modelo NIST/CPE).

Utiliza una Arquitectura Hexagonal (Puertos y Adaptadores) para separar la lógica de negocio principal de las herramientas de infraestructura (como syft y la base de datos PostgreSQL).

Características Principales

    Análisis de Imágenes Docker: Extrae información de cualquier imagen Docker local.

    Generación de SBOM: Utiliza syft para catalogar el sistema operativo, los paquetes del sistema (.deb, .apk, etc.) y los binarios (ej. Go).

    Detección de Vulnerabilidades Personalizada: Compara el inventario de paquetes contra una base de datos PostgreSQL propia para encontrar CVEs.

    Múltiples Formatos de Salida:

        Personalizado: Genera dos ficheros JSON (un inventario de activos y un informe de vulnerabilidades agrupado).

        DefectDojo (CycloneDX): Genera un informe JSON en formato CycloneDX v1.4, listo para ser importado en ASPM como DefectDojo, Snyk, o Dependency-Track.

        Resumen de Pipeline: Genera un JSON de resumen simple con el conteo de vulnerabilidades por severidad, ideal para CI/CD.

    Integración con ASPM: Permite especificar un project_name para la importación automática en DefectDojo.

    Configuración Segura: Gestiona las credenciales de la base de datos de forma segura usando un fichero .env.

Arquitectura

El proyecto sigue un diseño de Arquitectura Hexagonal para aislar la lógica central de las herramientas externas.

    Núcleo (Core):

        domain.py: Define los modelos de datos (ej. Package, VulnerabilityReport).

        ports.py: Define las interfaces (ej. ImageDataProvider, CveRepository).

        use_cases.py: Orquesta la lógica principal (ImageAnalyzerService) y devuelve los datos puros.

    Adaptadores (Adapters):

        syft_adapter.py: (Entrada) Implementa ImageDataProvider usando syft.

        postgres_cve_adapter.py: (Entrada) Implementa CveRepository consultando PostgreSQL.

        json_repository.py: (Salida) Implementa AnalysisRepository para guardar informes JSON personalizados.

        cyclonedx_adapter.py: (Salida) Adaptador para generar informes en formato CycloneDX.

        summary_adapter.py: (Salida) Adaptador para generar el JSON de resumen.

    Punto de Entrada (main.py):

        El "ensamblador" que lee los argumentos de la línea de comandos, carga el .env, "conecta" los adaptadores al núcleo y decide qué adaptador de salida utilizar.

Empezar

Prerrequisitos

Antes de empezar, asegúrate de tener todo esto instalado en tu sistema:

    Python 3.10+

    Docker: Debe estar instalado y en ejecución.

    Syft: La herramienta de syft debe estar instalada globalmente.
    Bash

        curl -sSfL https://raw.githubusercontent.com/anchore/syft/main/install.sh | sudo sh -s -- -b /usr/local/bin

    PostgreSQL: Una base de datos en ejecución y accesible (local o remota).

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

    generarl el esquema de BD y posteriormente lanzar una carga completa de cpe


Crea tu fichero de entorno: Crea un fichero llamado .env en la raíz del proyecto (docker_analyzer/.env) con tus credenciales.

Plantilla .env:

    DB_HOST=localhost
    DB_PORT=5432
    DB_NAME=vulnerabilities
    DB_USER=tu_usuario
    DB_PASS=tu_contraseña_secreta

    (Importante) Añade .env a tu .gitignore para no subir tus contraseñas a Git.

Uso

Uso: python3 -m src.main <imagen> <salida_activos.json> <salida_vulns.json> [OPCIONES]

Argumentos Posicionales:
  image                 Nombre de la imagen Docker (ej. 'nginx:1.10.3')
  output_asset          Ruta del fichero de salida para los activos (ej. 'activos.json')
  output_vuln           Ruta del fichero de salida para las vulnerabilidades (ej. 'vulns.json')

Argumentos Opcionales:
  --formato {custom,defectdojo}
                        Formato de salida:
                        'custom': (Default) Genera dos ficheros JSON personalizados.
                        'defectdojo': Genera un solo fichero CycloneDX en la ruta de 'output_vuln'.

  --project_name "Nombre"
                        Nombre del proyecto en DefectDojo (usado con --formato defectdojo).

  --summary_file RUTA
                        Ruta para un JSON de resumen de severidades (ej. 'resumen.json').


Ejemplo

python3 -m src.main nginx:1.10.3 activos.json vulns_dd.json \
  --formato defectdojo \
  --project_name "Mi Proyecto Nginx" \
  --summary_file resumen.json

Contenido de resumen.json:

{
    "total_vulnerabilities": 115,
    "severity_counts": {
        "critical": 0,
        "high": 20,
        "medium": 85,
        "low": 10,
        "none": 0,
        "unknown": 0
    }
}

ASMP compatibles
    • OWASP DefectDojo
    • Snyk
    • OWASP Dependency-Track
    • GitLab
    • GitHub
