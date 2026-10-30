# Kernveil — documentación en español

Kernveil es una plataforma experimental y local de referencia para evaluar solicitudes operativas sintéticas según políticas explícitas, autorización, estado, vigencia de datos y evidencias. La siguiente etapa propuesta, **Kernveil Resilience Lab**, amplía esta base hacia la validación de confianza en las comunicaciones y las pruebas reproducibles de inyección de fallos.

El MVP de portfolio combina un núcleo genérico de evaluación de políticas con adaptadores de simulación específicos. Los ejemplos actuales incluyen un escenario ferroviario ilustrativo y operaciones IT genéricas, ambos con datos sintéticos y sin ejecución ni actuación externa.

> **Límite de seguridad:** es un prototipo de investigación y portfolio. No es un enclavamiento ferroviario, un sistema de protección automática de trenes, un controlador industrial, una pasarela operativa de seguridad ni un componente certificado. No debe conectarse a infraestructuras operativas, señalización, frenado, despacho, PLC/SCADA, producción ni sistemas críticos. Ninguna tecnología puede garantizar riesgo cero o eliminar todos los fallos.

## Principios
- Denegar por defecto ante datos esenciales ausentes, caducados, incoherentes o sin autorización.
- Explicar cada decisión con códigos de motivo estables y evidencia estructurada.
- Separar el núcleo genérico de las reglas específicas de cada dominio.
- Evaluar sin ejecutar ni accionar comandos externos.
- Probar también los fallos, no solo los casos correctos.
- Evolucionar hacia pruebas sintéticas de integridad de comunicaciones y resiliencia.

## Estructura
- src/sentinel_interlock/: modelos, motor de evaluación y ledger en memoria.
- examples/demo.py: demostración reproducible de tres escenarios sintéticos.
- tests/: pruebas deterministas y pruebas basadas en propiedades.
- docs/: arquitectura, amenazas, límites de seguridad y hoja de ruta.

## Primer uso y demostración
Requisitos: Git y Python 3.12.

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

**macOS / Linux:**
```bash
python3.12 -m venv .venv
source .venv/bin/activate
python -m pip install -e ".[dev]"
python examples/demo.py
pytest
```

La demostración muestra una decisión ilustrativa ALLOW y dos DENY, con códigos de motivo y evidencia JSON versionada. Los datos son afirmaciones sintéticas, no datos de sensores confiables; no se ejecuta ningún comando ni se contacta con sistemas externos. ALLOW no constituye una garantía de seguridad real.

## Prácticas de ingeniería demostradas
- **Python con tipos y modelos validados:** modelos Pydantic en [models.py](../../src/sentinel_interlock/models.py).
- **Evaluación defensiva:** listas de autorización, control de vigencia y motivos de denegación en [engine.py](../../src/sentinel_interlock/engine.py).
- **Verificación automatizada:** [pruebas basadas en propiedades](../../tests/test_properties.py), [pruebas de serialización](../../tests/test_serialization.py) y [pruebas de sesión y repetición](../../tests/test_session.py).
- **Calidad del código:** Ruff y mypy estricto en [pyproject.toml](../../pyproject.toml).
- **Higiene de seguridad:** Bandit, pip-audit, GitGuardian y acciones de GitHub fijadas por SHA completo en [CI](../../.github/workflows/ci.yml).
- **Trazabilidad de riesgos:** [matriz de riesgos y pruebas](../risk-traceability.md).

## Kernveil Resilience Lab — dirección prevista
La siguiente etapa explorará la validación sintética de comunicaciones y las pruebas de resiliencia operativa: vigencia de mensajes, secuencia y detección de repetición, integridad, estados contradictorios, incertidumbre del reloj, interrupciones de servicios e inyección reproducible de fallos. El objetivo es medir cómo responde el prototipo ante fallos definidos explícitamente, no prometer riesgo cero.

Consulta el [diseño de Resilience Lab](../resilience-lab.md) y la [hoja de ruta](../roadmap.md). Estas capacidades están planificadas y todavía no forman parte del MVP implementado.

## Estado
Implementación de referencia en fase de portfolio. Las pruebas actuales solo demuestran las propiedades que cubren; no demuestran seguridad operativa ni idoneidad para producción.

## Documentación adicional
- [Arquitectura](../architecture.md)
- [Modelo de amenazas](../threat-model.md)
- [Límites de seguridad](../safety-boundary.md)
- [Trazabilidad de riesgos y pruebas](../risk-traceability.md)
- [Revisión del alcance del portfolio](../portfolio-scope-review.md)
- [Diseño de Kernveil Resilience Lab](../resilience-lab.md)
- [Hoja de ruta](../roadmap.md)

Consulta el [README canónico en inglés](../../README.md).
