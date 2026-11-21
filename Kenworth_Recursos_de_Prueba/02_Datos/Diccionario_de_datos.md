# Diccionario
CSV UTF-8 con BOM, coma como separador. JSON usa UTF-8. Tiempos ISO locales de Colombia, sin cambio de zona; no son UTC. Una fila de eventos es una observación, no un incidente confirmado. evento_id es único; bytes representa volumen observado, no contenido.

- inventario: activo_id único, nombre_prueba enlaza configuraciones y hallazgos; ip_prueba enlaza eventos; zona identifica segmento; criticidad es un supuesto; responsable_rol es un rol de prueba.
- eventos: origen_ip/destino_ip son etiquetas de red; puerto_destino es entero; accion es allow/deny; regla_id enlaza políticas (puede ser inconsistente); usuario_prueba no identifica personas; resultado es fallo/exito/-; tipo es trafico/autenticacion.
- políticas: origen/destino pueden ser zona, activo o any; servicio es descripción; no representa sintaxis de fabricante ni un motor de reglas completo.
- cambios: intervalo inclusive de inicio/fin, activo, origen_autorizado y usuario_prueba ayudan a contextualizar; limite indica qué no cubre el permiso.
- hallazgos: categoría y evidencia son hipótesis iniciales, no diagnóstico de un escáner. No se han asignado CVE ni puntuaciones CVSS.
- configuración: booleanos true/false; actualizaciones_pendientes no identifica versiones; respaldo_ultima_prueba puede ser «No registrada», lo que significa ausencia de evidencia, no prueba de que no existe respaldo.

Los IDs, IP y roles son de prueba; no contienen datos reales de Kenworth. Los eventos y políticas pueden discrepar intencionalmente: documentar la inconsistencia en vez de inventar una regla que la resuelva.
