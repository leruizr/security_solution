# LOG-SECURITY

Monitoreo de eventos y evaluación de vulnerabilidades · **Kenworth de la Montaña**

Reto **EstudIA** (Alcaldía de Medellín) · Capa 2 · Ciberseguridad básico
Equipo **E-8ZNU «security»** · Bloque 27, salón 303

**Tablero en vivo: <https://securitysolution-bay.vercel.app/>**

> **Todos los datos de este repositorio son de prueba.** No representan la
> infraestructura, los registros, las políticas ni las vulnerabilidades reales de
> Kenworth de la Montaña. El ejercicio se trabaja **100 % offline**: solo se leen
> archivos locales. No se escanea ni se conecta a ninguna IP.

---

## El problema

Kenworth no tiene un proceso estandarizado de monitoreo de eventos y alertas, ni
una evaluación continua de vulnerabilidades. Hoy se revisan ocasionalmente
algunos eventos del firewall, sin un proceso continuo. Eso es lo que hace falta
como base para cualquier plan de hardening.

## La solución

LOG-SECURITY convierte los registros crudos en un número corto de alertas
explicadas y priorizadas, separa las que ya tienen una explicación legítima de
las que requieren revisión real, y avisa por correo solo cuando algo es crítico.

---

# Qué nos entregaron y qué construimos

El curso entregó un paquete de recursos de prueba el 20 de noviembre de 2026. A
continuación, pieza por pieza, qué venía hecho y qué puso el equipo.

| Pieza | Lo entregado | Lo construido por el equipo |
|---|---|---|
| **1. Código validador** | Un analizador de 38 líneas con 4 reglas | 6 reglas, severidad, correlación y 615 líneas de Python |
| **2. Front de presentación** | Nada | Tablero de 6 vistas, 2.045 líneas de JavaScript |
| **3. Automatizaciones** | Nada | Flujo de notificación en n8n y despliegue continuo |
| **4. Validaciones** | 3 archivos de referencia | 7 pruebas ejecutadas, 3 de ellas nuevas |

---

## 1. El código validador

### Lo que nos entregaron

`Kenworth_Recursos_de_Prueba/06_Laboratorio/analizador.py`: **38 líneas** de
Python, escritas en una sola línea por bloque. Aplica **cuatro reglas** y escribe
un CSV y un resumen.

| # | Regla entregada |
|---|---|
| 1 | Fallos de autenticación repetidos en ventana móvil de 10 minutos |
| 2 | Acceso exitoso fuera del horario habitual (07:00–19:00) |
| 3 | Volumen por encima del umbral de revisión (50 MB) |
| 4 | Evento marcado con R01 que no coincide con su descripción |

También nos entregaron los datos: 324 eventos normalizados, el inventario de
10 activos, 7 hallazgos iniciales, el registro del cambio autorizado CH01, las
4 políticas del firewall y la configuración de 3 servidores.

**Lo que ese analizador NO hace:** no sabe qué activo está involucrado ni cuán
crítico es, no reconoce los cambios autorizados (así que marca como sospechoso
un mantenimiento aprobado), no prioriza, y no detecta ni los 12 intentos
bloqueados desde Internet contra la base de datos ni el uso de una regla del
firewall que no deja registro.

### Lo que construimos

**Reestructuramos el original sin tocar su lógica.** Lo reescribimos legible y
comentado, porque cinco personas lo van a extender. Comprobamos con `diff` que
sigue produciendo exactamente el mismo resultado.

**Dos reglas nuevas** (`detectar_ampliadas` en `analizador/analizador.py`):

| # | Regla del equipo | Qué encuentra en los datos de prueba |
|---|---|---|
| 5 | Escaneo de puertos (vertical o distribuido) hacia un activo crítico | Los 12 intentos bloqueados de `203.0.113.77` contra DB-LAB, en los puertos 22, 5432 y 3389 |
| 6 | Uso efectivo de una excepción del firewall que no deja registro | Los 8 eventos que pasaron por R02 hacia DB-LAB sin quedar en ninguna auditoría |

La regla 6 emite **una sola alerta por regla**, no una por evento: ocho avisos
del mismo problema serían fatiga de alertas. Y no está escrita contra R02: lee
las políticas y alerta sobre cualquier regla con `registro = no`.

**Enriquecimiento y severidad** (`analizador/severidad.py`), que el original no
tenía:

- Cruza cada alerta con el inventario: activo, zona y criticidad.
- **Correlaciona con los cambios autorizados.** Las tres alertas de las 02:00 se
  cierran solas con justificación trazable, porque CH01 ampara ese mantenimiento.
- Detecta que los fallos repetidos terminan en un **acceso exitoso**, y escala
  la señal por eso.
- Calcula `severidad = criticidad del activo × peso de la señal`, ambos de 1 a 3,
  la misma escala que la rúbrica usa para impacto × exposición.
  **9 = crítica** (dispara correo), 6 = alta, 3–4 = media, 1–2 = baja.

**Separación base / ampliadas.** Las 4 reglas del curso se numeran primero
(`AL001`–`AL006`) y las nuestras a continuación. Agregar una regla nunca desplaza
un identificador existente, lo que importa porque esos códigos están citados en
el expediente del equipo y guardados en la base de datos de alertas ya avisadas.

| Resultado | Entregado | Con LOG-SECURITY |
|---|---|---|
| Alertas generadas | 6 | 8 |
| Alertas con activo y criticidad | 0 | 8 |
| Falsos positivos cerrados automáticamente | 0 | 3 |
| Alertas clasificadas por severidad | 0 | 8 |
| Líneas de Python | 38 | 615 |

---

## 2. El front para presentar los datos

### Lo que nos entregaron

**Nada.** El analizador del curso escribe un CSV y un JSON. Para leerlos hay que
abrirlos en una hoja de cálculo.

### Lo que construimos

Un tablero de **seis vistas**, publicado en
<https://securitysolution-bay.vercel.app/>:

| Vista | Qué resuelve |
|---|---|
| **Panorama** | Las métricas de un vistazo: actividad por hora, alertas por severidad, tráfico por regla del firewall, volumen por destino y el estado de configuración de cada servidor |
| **Monitor** | Tabla de alertas con severidad y estado, tabla de eventos crudos, filtros en vivo, e importación de logs propios arrastrando el archivo |
| **Correlación** | La demostración central: un interruptor que cruza las alertas contra los cambios autorizados y muestra por qué una se descarta y otra de la misma hora no |
| **Hardening** | Matriz impacto × exposición con deslizadores que recalculan prioridades en vivo, y fichas con responsable, riesgo operativo, validación y reversión |
| **Validación** | Los casos controlados y la comparación entre los dos motores, ejecutables delante del jurado |
| **Entregables** | Canvas, ficha de incidente y guion de pitch, generados a partir de los datos cargados |

**Decisiones que vale la pena defender:**

- **Sin framework ni CDN.** JavaScript con módulos nativos y CSS propio. El
  tablero funciona completo sin conexión, que es lo que importa el día de la
  sustentación. No requiere instalar nada.
- **De la alerta a la evidencia en un clic.** La guía exige que otro equipo
  pueda llegar al registro que originó una alerta. Aquí es un botón.
- **El archivo importado nunca sale del equipo.** Se lee con `FileReader` en el
  navegador. Con logs reales, los registros no deben salir del perímetro.
- **Gráficos de una sola serie en un único tono azul** (`#3987e5`), validado
  sobre la superficie oscura: banda de luminosidad, croma y contraste 4.98:1.
  Los colores de estado nunca van solos, siempre con icono y texto, porque rojo
  y verde se confunden con daltonismo. Todo valor se puede leer como número.

---

## 3. Las automatizaciones

### Lo que nos entregaron

**Nada.** El analizador del curso se ejecuta a mano y escribe archivos.

### Lo que construimos

**Notificación de alertas críticas con n8n.** El flujo `LOG-SECURITY · Alertas
críticas` recibe las alertas por un webhook, descarta las ya avisadas, arma un
solo correo en HTML y lo envía por Gmail:

```
POST /webhook/alertas-kenworth
  → Separar cada alerta
  → Descartar las ya notificadas     (consulta la Data Table)
  → ¿Hay alertas nuevas?
  → Armar el correo  →  Enviar por Gmail
  → Registrar como notificadas       (escribe en la Data Table)
```

- **Un solo correo, nunca uno por alerta.** Seis correos serían fatiga de alertas.
- **Doble filtro.** El analizador solo envía severidad 9 y el flujo lo vuelve a
  comprobar, por si alguien descubriera la URL del webhook.
- **El dedup vive en una Data Table de n8n**, no en un archivo local, para que
  sirva a todo el equipo y no por computador.
- **El registro va después del envío.** Si el correo falla, la alerta no queda
  marcada y se reintenta. Al revés se perdería.
- **Nunca bloquea.** Sin internet, el análisis sigue siendo válido.
- **Sin dependencias.** El envío usa `urllib` de la librería estándar.

**Despliegue continuo.** Cada push a `main` actualiza el tablero en Vercel sin
intervención.

---

## 4. Las validaciones

### Las que vinieron hechas

El curso entregó `07_Validacion/` con tres archivos de referencia, producidos por
**su** analizador:

| Archivo | Qué contiene |
|---|---|
| `Referencia_alertas.csv` | Las 6 alertas que debe producir el analizador entregado |
| `Referencia_resumen.json` | Los conteos por tipo de esas 6 alertas |
| `Casos_controlados.json` | 4 casos de frontera, **con el resultado esperado y el observado ya rellenos** |

Es decir: el curso ya había probado su propio analizador y nos dejó el resultado
como patrón de comparación. No son pruebas que hayamos diseñado nosotros.

### Las que ejecutamos nosotros

| # | Prueba | Nueva | Estado | Resultado |
|---|---|:---:|---|---|
| 1 | Las 4 reglas del curso siguen reproduciendo `Referencia_alertas.csv` después de reescribir el código y agregar 2 reglas | | ✅ | Cero diferencias |
| 2 | Los 4 casos controlados, ejecutados contra **nuestro** motor y en vivo desde el tablero | | ✅ | 0, 1, 0 y 1 alerta, como se esperaba |
| 3 | **Validación cruzada: el motor de Python y el de JavaScript dan el mismo resultado** | ★ | ✅ | Cero diferencias en 12 campos sobre las 8 alertas |
| 4 | **Importar logs propios en CSV, JSON y JSONL, y rechazar un archivo mal formado** | ★ | ✅ | 324 eventos en los tres formatos, mismas alertas; el archivo inválido se rechaza con mensaje claro |
| 5 | **El notificador no reenvía una alerta ya avisada** | ★ | ✅ | Tres ejecuciones seguidas: un solo correo, la tabla quedó con 2 filas |
| 6 | El correo de alerta crítica llega a la bandeja | | ✅ | Recibido, con las 2 alertas de severidad 9 |
| 7 | Otro equipo encuentra por sí solo la evidencia detrás de una alerta | | ⏳ | Pendiente |

★ = prueba que no existía en el paquete entregado.

La **prueba 3** merece una explicación: como el tablero permite cargar un archivo
propio y recalcular en el navegador, las reglas existen dos veces, en Python y en
JavaScript. Dos implementaciones de lo mismo pueden separarse sin que nadie lo
note. Por eso el tablero las compara en vivo y tiene que seguir dando cero
diferencias.

### Cómo reproducirlas

```bash
python3 analizador/analizador.py
diff salidas/alertas_base.csv Kenworth_Recursos_de_Prueba/07_Validacion/Referencia_alertas.csv
```

Sin diferencias. Las pruebas 2 y 3 se ejecutan desde la vista **Validación** del
tablero, con un botón cada una.

---

# Usar el proyecto

El tablero está publicado y no requiere instalar nada:
<https://securitysolution-bay.vercel.app/>

### Regenerar los datos

```bash
python3 analizador/analizador.py
```

Requiere **Python 3.9 o superior**. No instala paquetes, no usa internet.

| Archivo generado | Para qué |
|---|---|
| `salidas/alertas.csv` | Todas las alertas: revisión manual y plantillas |
| `salidas/alertas_base.csv` | Solo las 4 reglas del curso, para validar |
| `salidas/resumen.json` | Conteos por tipo |
| `web/alertas.json` | **El contrato de datos** que consume el tablero |

### Enviar las alertas críticas

```bash
python3 analizador/analizador.py --notificar
```

Opcional y desactivado por defecto. La URL del webhook vive en
`config/notificaciones.json`, que **no se versiona**: un webhook es un endpoint
abierto. Se parte de `config/notificaciones.ejemplo.json`.

### Trabajar en el tablero

```bash
cd web && python3 -m http.server 8000
```

Solo para desarrollo. Abrir el archivo con doble clic **no funciona**: el
navegador bloquea la lectura de módulos bajo `file://`.

---

## Estructura

```
.
├── analizador/
│   ├── analizador.py      Detección: 4 reglas del curso + 2 del equipo
│   ├── severidad.py       Activo, correlación con cambios y severidad
│   └── notificador.py     Envío opcional al webhook de n8n
├── web/                   Tablero estático. Es lo que se despliega en Vercel
│   ├── js/motor.js            Espejo en JavaScript del motor de Python
│   ├── js/ingesta.js          Lectura de CSV / JSON / JSONL en el navegador
│   └── js/vistas/             Una vista por módulo
├── salidas/               Resultados de cada corrida
├── docs/                  Plantillas del curso que el equipo diligencia
├── config/                Configuración local. El archivo real no se versiona
├── n8n/                   Diseño del flujo de notificación
└── Kenworth_Recursos_de_Prueba/
                           Paquete entregado por el curso. SE DEJA INTACTO:
                           es la fuente de datos y la base de comparación
```

> **Atribución.** La carpeta `Kenworth_Recursos_de_Prueba/` es material didáctico
> entregado por el programa EstudIA; no es autoría del equipo. Se incluye para
> que el análisis sea reproducible. El trabajo propio del equipo es todo lo demás.
> El documento de contexto del proyecto no se publica por contener información
> real de la empresa.

---

## Límites reconocidos

- Una alerta es una **señal para revisión**, no un incidente confirmado.
- No prueba intrusión, no atribuye un atacante y no demuestra extracción de datos.
- Las actualizaciones pendientes **no** permiten inferir CVE concretas: faltan
  versiones, boletines y validación técnica.
- Un respaldo «No registrado» significa **ausencia de evidencia**, no que el
  respaldo no exista.
- Un solo día de datos y sin User-ID activo: no se puede asociar una IP a una
  persona ni establecer una tendencia.
- El analizador no interpreta sintaxis de Palo Alto ni sustituye un SIEM.
- En producción con logs reales, el tablero se despliega **on-premise o en la
  nube privada de la empresa**: los registros de firewall no deben salir de su
  perímetro.

## Equipo

| Integrante | Rol |
|---|---|
| Luis Enrique Ruiz Restrepo | Analista de configuración e integración |
| Zara Zapata Mariaca | Verificador |
| Maria Camila Garcia Castrillon | Relator |
| Luis Alexander Ramirez Valencia | Analista de eventos |
| Jhojan Steven Cano Florez | Responsable de activos |
| Adyuer De Jesus Ojeda Badel | Responsable de activos |
