# Propósito y límites

Construyan un MVP que ayude a la Dirección de Tecnología a revisar eventos, priorizar hallazgos y proponer un plan de hardening. El reto no exige atacar sistemas ni desplegar un firewall. El paquete sustituye únicamente los insumos pendientes con recursos de prueba.

Todo el trabajo se realiza sobre archivos locales. Las IP solo nombran elementos del escenario. No prueben accesos, escaneos o cambios en la red de EAFIT, Kenworth o terceros. Ninguno de esos accesos es necesario para completar el ejercicio.

Lean alcance, topología e inventario; luego contrasten eventos, políticas, cambios y configuraciones. La ficha original se conserva, pero las autorizaciones y datos sensibles mencionados allí no se presuponen recibidos.

# Ruta de construcción del MVP

Elijan un producto acotado: tablero de eventos con alertas explicadas, clasificador de hallazgos o checklist de hardening con evidencia y seguimiento. Pueden combinar dos funciones sencillas si alcanzan a probarlas.

Ruta sugerida: 20 minutos para entender activos y usuario; 30 para explorar e integrar; 50 para construir; 30 para priorizar y diseñar recomendaciones; 30 para probar y documentar. Ajusten la ruta a la guía oficial y conserven sus pausas.

Sin código: importen los CSV en una hoja de cálculo, filtren eventos, agrupen por origen y destino y documenten alertas. Con código: ejecuten el analizador incluido como punto de partida. No se requiere software de pago ni conexión a internet.

Entregable mínimo: al menos dos alertas justificadas, una de ellas contrastada con una fuente adicional; tres mejoras priorizadas con evidencia; una prueba realizada; y un límite reconocido. El equipo puede ampliar el alcance sin convertir el ejemplo en una solución definitiva.

# Cómo analizar eventos sin precipitar conclusiones

Separen evento, alerta e incidente: una observación es un evento; una regla puede generar una alerta; la revisión de contexto permite decidir si hay un incidente. Un bloqueo del firewall no prueba por sí mismo una intrusión.

Busquen fallos de autenticación repetidos en una ventana móvil de 10 minutos y revisen el acceso exitoso posterior. Esto amerita revisión, pero no demuestra que las credenciales fueron comprometidas. Comparen activo, regla aplicada y configuración.

Revisen actividad fuera del horario de prueba 07:00-19:00. Antes de escalar, contrasten cambios_autorizados.csv: una revisión de respaldo está autorizada de 02:00 a 02:30 desde ADMIN-LAB, sin autorizar cualquier tráfico del servidor.

Un volumen alto hacia un destino externo es una señal para investigar, no evidencia concluyente de extracción. Comparen la regla registrada con origen, destino y servicio. El laboratorio incluye una inconsistencia de reglas para practicar calidad y trazabilidad.

# Priorizar y recomendar hardening

Prioridad didáctica: puntúen impacto de 1 a 3 y exposición de 1 a 3, multipliquen y argumenten ambas dimensiones. De 6 a 9, alta; de 3 a 4, media; de 1 a 2, baja. No es CVSS ni una metodología oficial de la empresa.

Para cada recomendación registren hallazgo, activo, evidencia, cambio propuesto, responsable por rol, beneficio esperado, posible efecto sobre la operación, validación y reversión. Propongan restringir permisos y mejorar registros, evitando recomendaciones como «bloquear todo».

Las actualizaciones pendientes no permiten inferir vulnerabilidades concretas: faltan versiones, boletines y validación técnica. Registren qué información se debe solicitar. Tampoco asuman que un respaldo existe o funciona solo por tener un servidor de copias.

Los cambios se documentan como propuestas. El laboratorio no aplica configuraciones reales. La prueba de restauración, la segmentación y la autenticación requieren revisión de responsables antes de cualquier implementación empresarial.

# Ejecutar el laboratorio local

Con Python 3.10 o superior, desde la carpeta del paquete ejecuten: python 06_Laboratorio/analizador.py. No requiere instalar paquetes. Si Python no está disponible, el mismo análisis puede hacerse filtrando CSV en una hoja de cálculo.

El analizador solo lee archivos del paquete y escribe Salidas/alertas.csv y Salidas/resumen.json. Detecta fallos repetidos con ventana móvil, volumen alto, accesos exitosos fuera de horario e inconsistencia simplificada de R01. No abre conexiones, escanea ni modifica servicios.

Los umbrales pueden cambiarse en 03_Configuraciones/parametros_alertas.json. El analizador no es un SIEM ni interpreta sintaxis Palo Alto. No evalúa automáticamente todos los hallazgos: el contraste humano es parte del ejercicio.

El archivo de alertas es una referencia inicial; el equipo debe enriquecerlo con evidencia y disposición: revisar, cerrar con justificación o escalar. No contabilicen cada alerta como un incidente diferente sin correlacionar.

# Validación y presentación

Prueben el umbral exacto de cinco fallos, un caso de cuatro fallos, una ventana mayor a diez minutos y la actividad autorizada de respaldo. Los casos controlados y resultados de referencia están en 07_Validacion; los profesores tienen orientaciones separadas.

Pidan a otro equipo que use el MVP e identifique la evidencia detrás de una alerta. Registren resultado esperado, observado y mejora. No basta con afirmar que el tablero abre.

En la presentación expliquen usuario y problema, muestren un caso del MVP, argumenten prioridades y aclaren limitaciones. Distingan lo observado en los archivos de lo que tendrían que confirmar con la empresa.

Empiecen por LEEME.md y utilicen las plantillas editables. Los ejemplos y las respuestas de referencia sirven para aprender y contrastar; no sustituyen la construcción ni las decisiones del equipo.