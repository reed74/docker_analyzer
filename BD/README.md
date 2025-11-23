# NVD CVE Importer for PostgreSQL

Este proyecto es una herramienta ETL (Extract, Transform, Load) escrita en Python que sincroniza la Base de Datos Nacional de Vulnerabilidades (NVD) del NIST con una base de datos PostgreSQL local.

Utiliza la **API 2.0** oficial del NIST y soporta tanto cargas históricas completas como actualizaciones incrementales diarias.

# Características

* **Soporte API NVD 2.0:** Cumple con el estándar actual del NIST.
* **Carga Histórica:** Descarga e inserta todas las vulnerabilidades desde 2002 hasta la fecha.
* **Actualización Incremental:** Modo ligero para descargar solo los cambios de las últimas 24 horas (o días personalizados).
* **Normalización CPE:** Parsea cadenas CPE 2.3 (`cpe:2.3:a:vendor:product...`) y las normaliza en columnas de base de datos.
* **Gestión de Duplicados:** Utiliza *Upserts* (`ON CONFLICT`) para actualizar registros existentes sin duplicar datos.
* **Resiliencia:** Descarga los datos a disco (`json`) antes de procesar para evitar pérdida de datos por fallos de red.

## Prerrequisitos

* Python 3.8 o superior.
* PostgreSQL 12 o superior.
* (Opcional pero recomendado) [API Key de NVD](https://nvd.nist.gov/developers/request-an-api-key) para mayor velocidad de descarga.

## Instalación y Configuración


```bash
python3 -m venv venv
source venv/bin/activate  

pip install -r requirements.txt


Crear un archivo ENV en el que se pueda especifiar la conexión de BD y el API de NIST

# .env
DB_NAME=nombre_de_tu_bd
DB_USER=tu_usuario
DB_PASS=tu_contraseña
DB_HOST=localhost
DB_PORT=5432
NVD_API_KEY=tu_api_key_aqui



Carga Inicial (Full History)

Utiliza este comando la primera vez. Descargará todo el historial de CVEs. Advertencia: Esto puede tardar varias horas dependiendo de tu conexión y si tienes API Key.
En caso de solicitar la opción --full se ejecutra un truncate en las tablas, por lo que el esquema deberá de existir.

    python etl_nvd.py --full

Actualización Diaria (Incremental)

Utiliza este comando para mantener la base de datos al día. Busca cambios en las últimas 24 horas.

    python etl_nvd.py --incremental

Opciones adicionales: Si necesitas recuperar cambios de más días (ej. el script falló el fin de semana), usa el argumento --days:

    python etl_nvd.py --incremental --days 3

Para mantener la base de datos actualizada automáticamente, configura una tarea programada.

Linux (Crontab)

Ejemplo de ejecución a las 3 de la mañana todos los días, por defecto el incremental es de un dá


0 3 * * * /ruta/a/tu/venv/bin/python /ruta/al/proyecto/etl_nvd.py --incremental


Notas sobre la API de NVD

    Sin API Key: El script espera automáticamnte 6 segundos entre peticiones para evitar el error HTTP 403.

    Con API Key: El tiempo de espera se reduce a 0.6 segundos.