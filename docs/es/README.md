# Kernveil — documentación en español

**Prototipo local de validación de eventos operativos y resiliencia.**

Kernveil es un proyecto experimental en Python para evaluar la fiabilidad de eventos operativos sintéticos, detectar determinadas incoherencias y fallos de comunicación, y generar evidencias explicables. El núcleo es independiente del dominio; el transporte es la primera familia de aplicación y la simulación de incidencias viales será el primer nuevo demostrador. Los adaptadores ferroviarios, aeronáuticos y marítimos son posibles etapas posteriores.

El MVP actual combina un motor genérico de evaluación de políticas con ejemplos sintéticos ferroviarios y de operaciones IT. La validación inicial de eventos ya está implementada en `sentinel_interlock.events`: sobre versionado, lista de fuentes declaradas, vigencia, caducidad, secuencia, repetición e integridad del payload mediante digest. La correlación, la inyección de fallos y los adaptadores de resiliencia multidominio siguen planificados.

> **Límite de seguridad:** es un prototipo de investigación y portfolio. No es un servicio de navegación, una plataforma de gestión del tráfico, un enclavamiento ferroviario, un sistema de control aeronáutico o marítimo, un controlador industrial ni un componente certificado. No debe conectarse a infraestructuras reales, vehículos, señalización, frenado, despacho, controladores de semáforos, PLC/SCADA o sistemas de producción. No emite instrucciones de circulación ni determina prioridades de paso. Ninguna tecnología garantiza riesgo cero o elimina todos los fallos.

## Principios del producto

- Tratar origen, vigencia, integridad, secuencia y contexto como aspectos explícitos de validación.
- Distinguir información inválida, caducada, duplicada, contradictoria, desconocida o indeterminada.
- Denegar por defecto cuando la política configurada exige evidencias fiables.
- Explicar los resultados mediante códigos de motivo estables y evidencias estructuradas.
- Separar el núcleo genérico de la semántica y las hipótesis específicas de cada dominio.
- Simular fallos de forma reproducible, sin ejecutar comandos ni accionar sistemas externos.

## Estrategia por dominios

El núcleo es reutilizable, pero los adaptadores de cada dominio no son intercambiables. El primer demostrador nuevo será la gestión simulada de incidencias viales: semáforos fuera de servicio, colisiones, obstáculos, cierres de carretera, avisos duplicados o caducados y reportes contradictorios. Los escenarios ferroviarios existentes se mantienen. Los dominios marítimo y aeronáutico solo se abordarán después de elaborar modelos de amenazas y supuestos específicos y obtener revisión especializada.

Kernveil no pretende ser otro Waze o Google Maps. No ofrece navegación en tiempo real ni sustituye los avisos oficiales. Explora una capa independiente que evalúa si la información sintética es suficientemente actual, coherente y fiable para un flujo de avisos.

## Estructura actual

- src/sentinel_interlock/: modelos, motor de evaluación y ledger en memoria.
- examples/demo.py: demostración de tres evaluaciones de políticas sintéticas.
- tests/: pruebas deterministas y pruebas basadas en propiedades.
- docs/: arquitectura, amenazas, límites de seguridad y hoja de ruta.

## Primer uso

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

La demostración actual muestra una decisión ilustrativa ALLOW y dos DENY, con códigos de motivo y evidencia JSON versionada. Los datos son afirmaciones sintéticas, no datos de sensores confiables; no se ejecuta ningún comando ni se contacta con sistemas externos. ALLOW no constituye una garantía de seguridad real.

## Prácticas de ingeniería demostradas

- **Python con tipos y modelos validados:** modelos Pydantic en [models.py](../../src/sentinel_interlock/models.py).
- **Evaluación defensiva:** listas de autorización, control de vigencia y motivos de denegación en [engine.py](../../src/sentinel_interlock/engine.py).
- **Verificación automatizada:** [pruebas basadas en propiedades](../../tests/test_properties.py), [pruebas de serialización](../../tests/test_serialization.py) y [pruebas de sesión y repetición](../../tests/test_session.py).
- **Calidad del código:** Ruff y mypy estricto en [pyproject.toml](../../pyproject.toml).
- **Higiene de seguridad:** Bandit, pip-audit, GitGuardian y acciones de GitHub fijadas por SHA completo en [CI](../../.github/workflows/ci.yml).
- **Trazabilidad de riesgos:** [matriz de riesgos y pruebas](../risk-traceability.md).

## Kernveil Resilience Lab — planificado

La siguiente etapa añadirá reglas de correlación, inyección reproducible de fallos y un simulador de incidencias viales: semáforos averiados e informes contradictorios o caducados. Todos los datos serán sintéticos y el funcionamiento será local.

Consulta el [diseño de Resilience Lab](../resilience-lab.md) y la [hoja de ruta](../roadmap.md). Estas capacidades están planificadas, no implementadas en el MVP actual.

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
