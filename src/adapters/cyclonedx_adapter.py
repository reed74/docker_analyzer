import os
from packageurl import PackageURL
from cyclonedx.model.bom import Bom, BomMetaData  # <-- CORRECCIÓN 1
from cyclonedx.model.component import Component, ComponentType
import cyclonedx.model.vulnerability as cdx_vuln
# (Ya no importamos VulnerabilityTarget)
from cyclonedx.output import make_outputter, OutputFormat
from cyclonedx.schema import SchemaVersion
from src.core.domain import AssetReport, VulnerabilityReport, Vulnerability
from typing import Optional

class CycloneDxAdapter:
    """
    Genera un informe CycloneDX en formato JSON,
    combinando activos y vulnerabilidades
    (cyclonedx-python-lib v6.4.4)
    """
    
    def save(self, asset_report: AssetReport, vuln_report: VulnerabilityReport, 
             output_path: str, project_name: Optional[str] = None):
        
        bom = Bom()
        
        if not project_name:
            project_name = asset_report.image_name
        
        main_component = Component(
            name=project_name,
            type=ComponentType.APPLICATION,
            bom_ref=project_name
        )
        bom.metadata = BomMetaData(component=main_component) # <-- CORRECCIÓN 1
        
        # 1. Mapear paquetes a Componentes 
        component_map = {} 
        for pkg in asset_report.packages:
            if not pkg.purl:
                continue 

            try:
                p = PackageURL.from_string(pkg.purl)
                c = Component(
                    name=p.name,
                    version=p.version,
                    purl=p,
                    bom_ref=pkg.purl
                )
                bom.components.add(c)
                component_map[pkg.product] = c
            except ValueError:
                print(f"Advertencia: PURL inválido, saltando componente: {pkg.purl}")

        # 2. Mapear vulnerabilidades
        all_vulns = vuln_report.os_vulnerabilities + vuln_report.package_vulnerabilities
        
        for vuln in all_vulns:
            severity = cdx_vuln.VulnerabilitySeverity.UNKNOWN
            if vuln.severity:
                try:
                    severity_upper = str(vuln.severity).upper()
                    if severity_upper == "NEGLIGIBLE": severity_upper = "NONE"
                    if severity_upper in cdx_vuln.VulnerabilitySeverity.__members__:
                        severity = cdx_vuln.VulnerabilitySeverity[severity_upper]
                except (KeyError, AttributeError):
                    pass

            v = cdx_vuln.Vulnerability(
                id=vuln.cve_id,
                source=cdx_vuln.VulnerabilitySource(name="BD-Personalizada"),
                ratings=[cdx_vuln.VulnerabilityRating(severity=severity)],
                description=f"Vulnerabilidad {vuln.cve_id}"
            )
            
            # 3. Enlazar la vulnerabilidad al componente afectado

            if vuln.package_name in component_map:
                component = component_map[vuln.package_name]
                v.affects.add(component.bom_ref)
            bom.vulnerabilities.add(v)

        # 4. Escribir el fichero JSON
        try:
            outputter = make_outputter(bom=bom, output_format=OutputFormat.JSON, schema_version=SchemaVersion.V1_4)
            
            with open(output_path, 'w') as f:
                f.write(outputter.output_as_string(indent=4))
            
        except Exception as e:
            print(f"Error al generar el informe CycloneDX: {e}")