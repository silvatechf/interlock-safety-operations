# Sentinel Interlock — documentación en español

Sentinel Interlock es una implementación experimental y local de referencia para evaluar si un comando operativo debe permitirse según una política explícita, la autorización, el estado, la vigencia de los datos y la evidencia disponible.

El proyecto combina un núcleo genérico de evaluación de políticas con adaptadores de simulación específicos. Los ejemplos actuales incluyen un escenario ferroviario ilustrativo y operaciones IT genéricas, ambos con datos sintéticos y sin ejecución ni actuación externa.

> **Límite de seguridad:** es un MVP educativo y de portfolio. No es un enclavamiento ferroviario, un sistema de protección automática de trenes, un controlador industrial de seguridad ni un componente certificado. No debe conectarse a infraestructuras operativas, señalización, frenado, PLC, producción ni sistemas críticos.

## Principios

- Denegar por defecto ante datos esenciales ausentes, caducados, incoherentes o sin autorización.
- Explicar cada decisión con códigos de motivo estables y evidencia estructurada.
- Separar el núcleo genérico de las reglas específicas de cada dominio.
- Evaluar sin ejecutar ni accionar comandos externos.
- Probar también los fallos, no solo los casos correctos.

## Estructura

- `src/sentinel_interlock/`: modelos, motor de evaluación y ledger en memoria.
- `examples/demo.py`: demostración reproducible de tres escenarios sintéticos.
- `tests/`: pruebas deterministas y pruebas basadas en propiedades.
- `docs/`: arquitectura, amenazas, límites de seguridad y hoja de ruta.
- `.github/workflows/`: integración continua, análisis estático y auditoría de dependencias.

## Primer uso y demostración

Requisitos: Git y Python 3.12. Clona el repositorio y entra en su directorio:

```shell
git clone https://github.com/silvatechf/interlock-safety-operations.git
cd interlock-safety-operations
```

**Windows PowerShell:**

```powershell
py -3.12 -m venv .venv
.\.venv\Scripts\Activate.ps1
python -m pip install -e ".[dev]"
python examples/demo.py
pytest
```

**macOS / Linux (Bash o shell compatible):**

```bash
python3.12 -m venv .venv
source .venv/bin/activate
python -m pip install -e ".[dev]"
python examples/demo.py
pytest
```

La demostración muestra una decisión ilustrativa `ALLOW` y dos `DENY`, con códigos de motivo y evidencia JSON versionada. Los identificadores y las marcas de tiempo varían entre ejecuciones. Los datos son afirmaciones sintéticas, no datos de sensores confiables; no se ejecuta ningún comando ni se contacta con sistemas externos. Un resultado `ALLOW` no constituye una garantía de seguridad real.

## Prácticas de ingeniería demostradas

- **Python con tipos y modelos validados:** modelos con Pydantic en [`models.py`](../../src/sentinel_interlock/models.py).
- **Evaluación defensiva:** listas de autorización, control de vigencia, datos obligatorios y motivos de denegación en [`engine.py`](../../src/sentinel_interlock/engine.py).
- **Verificación automatizada:** [pruebas basadas en propiedades](../../tests/test_properties.py), [pruebas de serialización de evidencias](../../tests/test_serialization.py) y [pruebas de sesión y repetición](../../tests/test_session.py).
- **Calidad del código:** configuración de Ruff y mypy estricto en [`pyproject.toml`](../../pyproject.toml).
- **Higiene de seguridad:** Bandit, pip-audit y acciones de GitHub fijadas por SHA completo en el [flujo de CI](../../.github/workflows/ci.yml); GitGuardian comprueba secretos en las solicitudes de cambio.
- **Trazabilidad de riesgos:** [matriz de riesgos y pruebas](../risk-traceability.md) con mitigaciones, pruebas concretas, arquitectura y limitaciones pendientes.

Estos enlaces permiten revisar el código y las pruebas que respaldan cada afirmación. Describen prácticas presentes en el repositorio; no significan que todos los riesgos estén eliminados ni que exista una verificación independiente.

Es un proyecto de portfolio local-first, no un producto de control operativo. Las pruebas solo demuestran las propiedades verificadas; no demuestran seguridad real ni certificación.

## Documentación adicional

- [Arquitectura](../architecture.md)
- [Modelo de amenazas](../threat-model.md)
- [Límites de seguridad](../safety-boundary.md)
- [Trazabilidad de riesgos y pruebas](../risk-traceability.md)
- [Revisión del alcance del portfolio](../portfolio-scope-review.md)
- [Hoja de ruta](../roadmap.md)

Consulta el [README canónico en inglés](../../README.md).
