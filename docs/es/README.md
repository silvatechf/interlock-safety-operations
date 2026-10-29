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
- `tests/`: pruebas deterministas.
- `docs/`: arquitectura, amenazas, límites de seguridad y hoja de ruta.
- `.github/workflows/`: integración continua.

Es un proyecto de portfolio local-first, no un producto de control operativo. Las pruebas solo demuestran las propiedades verificadas; no demuestran seguridad real ni certificación.

## Documentación adicional

- [Arquitectura](../architecture.md)
- [Modelo de amenazas](../threat-model.md)
- [Límites de seguridad](../safety-boundary.md)
- [Trazabilidad de riesgos y pruebas](../risk-traceability.md)
- [Revisión del alcance del portfolio](../portfolio-scope-review.md)
- [Hoja de ruta](../roadmap.md)

Consulta el [README canónico en inglés](../../README.md).
