/* Vista 4b: Entregables del reto, listos para copiar o exportar.
 *
 * Nota deliberada: no se nombra a ninguna persona real de la empresa. El usuario
 * objetivo se describe por su rol. El repositorio es publico.
 */
import { esc, el, copiar, descargar, bytes, numero } from '../ui.js';

let estado = null;
let activa = 'canvas';

function canvas(st) {
  const criticas = st.alertas.filter(a => a.estado === 'Abierta' && a.severidad_etiqueta === 'Crítica');
  return `# Canvas del MVP

**Equipo:** E-8ZNU «security» · EstudIA Capa 2 · Ciberseguridad básico
**Usuario objetivo:** la Dirección de Tecnología de la empresa, que hoy revisa
logs del firewall de forma ocasional y manual.

## Problema seleccionado
No existe un proceso estandarizado de monitoreo de eventos y alertas, ni una
evaluación continua de vulnerabilidades. Sin eso, cualquier plan de hardening se
construye sobre suposiciones.

## Función indispensable
Convertir ${numero(st.eventos.length)} registros crudos en un número corto de
alertas explicadas, separando las que ya tienen una explicación autorizada de las
que requieren revisión real.

## Qué hace
1. Aplica seis reglas de detección sobre los eventos normalizados: las cuatro
   del analizador de referencia más dos que agregó el equipo (denegaciones
   repetidas desde Internet hacia un activo crítico, y uso de una excepción del
   firewall que no deja registro).
2. Cruza cada alerta contra el inventario de activos y los cambios autorizados.
3. Calcula severidad como criticidad del activo × peso de la señal.
4. Prioriza los hallazgos con impacto × exposición y propone fichas de hardening
   con validación y reversión.

## Fuentes de evidencia
Eventos normalizados, inventario de activos, políticas de firewall, registro de
cambios autorizados y configuración de servidores. Todos del paquete de prueba
entregado por el curso.

## Resultado sobre el conjunto de prueba
${st.alertas.length} alertas: ${st.alertas.filter(a => a.estado === 'Descartada').length}
descartadas por cambio autorizado y ${st.alertas.filter(a => a.estado === 'Abierta').length}
abiertas, de las cuales ${criticas.length} son críticas.

## Qué NO hace el MVP
- No confirma incidentes: entrega señales para revisión humana.
- No prueba intrusión, no atribuye un atacante y no demuestra extracción de datos.
- No infiere vulnerabilidades concretas a partir de «actualizaciones pendientes»:
  faltan versiones, boletines y validación técnica.
- No interpreta sintaxis nativa de un fabricante de firewall ni sustituye un SIEM.
- Trabaja sobre un solo día de datos: no establece una línea base ni una tendencia.

## Cómo se comprueba
- Las cuatro reglas de referencia reproducen sin diferencias las 6 alertas del
  curso, aunque el equipo haya agregado dos reglas más.
- Los 4 casos controlados pasan: 4 fallos sin alerta, 5 fallos con alerta,
  5 fallos dispersos sin alerta y frontera de 10 minutos inclusive.
- El motor del navegador y el de Python producen el mismo resultado.
- Otro equipo debe poder llegar de una alerta a su evidencia en un clic.`;
}

function fichaIncidente(st) {
  const a = st.alertas.find(x => x.estado === 'Abierta' && x.tipo === 'Volumen para revisión');
  if (!a || !a.evento) return '# Ficha de revisión\n\nNo hay una alerta de volumen abierta en el conjunto actual.';
  const e = a.evento;
  const c = (st.cambios_autorizados || [])[0];

  return `# Ficha de revisión de posible incidente

**Fecha de apertura:** al cargar el conjunto de prueba
**Alerta origen:** ${a.alerta_id} (${a.tipo}) y ${st.alertas.filter(x => x.evento_id === e.evento_id).map(x => x.alerta_id).join(', ')}
**Severidad:** ${a.severidad_etiqueta} (${a.severidad})

## Hechos observados
El evento ${e.evento_id}, del ${e.fecha_hora.replace('T', ' a las ')}, registra una
transferencia de ${numero(e.bytes)} bytes (${bytes(e.bytes)}) desde ${a.activo}
(${e.origen_ip}) hacia ${e.destino_ip}, un destino que no está en el inventario,
por el puerto ${e.puerto_destino}. Supera el umbral de revisión de
${numero(st.parametros.volumen_revision_bytes)} bytes.

El evento aparece registrado con la regla ${e.regla_id}, que según las políticas
describe tráfico de Internet hacia el portal web por TCP/443. Ni el origen ni el
destino corresponden. Es una inconsistencia de registro.

## Cronología
${st.alertas.filter(x => x.cambio_id).map(x => `- ${x.fecha_hora.slice(11, 16)} · ${x.evento_id} · ${x.tipo} · cubierto por ${x.cambio_id}`).join('\n')}
- ${e.fecha_hora.slice(11, 16)} · ${e.evento_id} · salida de ${bytes(e.bytes)} hacia ${e.destino_ip} · NO cubierto

## Activos relacionados
${a.activo} (${e.origen_ip}), zona ${a.zona}, criticidad ${a.criticidad}.

## Contraste con el cambio autorizado
${c ? `El cambio ${c.cambio_id} autoriza «${c.motivo}» sobre ${c.activo}, de
${c.inicio.slice(11, 16)} a ${c.fin.slice(11, 16)}, desde ${c.origen_autorizado}
con el usuario ${c.usuario_prueba}. El evento ocurre dentro de esa ventana, pero:

- el origen es ${e.origen_ip}, no ${c.origen_autorizado};
- el destino es externo, no el activo del cambio;
- el límite declarado del cambio es: «${c.limite}».

Coincide únicamente la hora. La coincidencia horaria no es una autorización.` : 'No hay cambios autorizados registrados.'}

## Hipótesis y evidencia faltante
Hipótesis: salida de datos no autorizada desde el servidor de respaldo.
**No está demostrada.** Para sostenerla o descartarla hace falta:
- Confirmar con la empresa si existe un proceso legítimo de réplica externa.
- Obtener el registro de sesión del servidor en esa franja.
- Verificar por qué el evento quedó etiquetado con una regla que no corresponde.
- Conocer la retención de logs disponible para reconstruir días anteriores.

## Acciones propuestas (no ejecutadas)
1. Solicitar a la empresa el contexto del destino externo.
2. Revisar la asignación de reglas de registro en el firewall.
3. Priorizar la activación del registro centralizado del activo.

## Escalamiento por rol
Infraestructura (responsable del servidor de respaldo) y Redes (responsable de
las reglas del firewall), con conocimiento de la Dirección de Tecnología.

## Decisión
Se mantiene **abierta** como posible incidente. No se declara incidente
confirmado: con los datos disponibles no se puede afirmar que hubo extracción
de información.`;
}

function pitch(st) {
  const criticas = st.alertas.filter(a => a.estado === 'Abierta' && a.severidad_etiqueta === 'Crítica').length;
  const descartadas = st.alertas.filter(a => a.estado === 'Descartada').length;
  return `# Guion de pitch · 3 a 5 minutos

## 1. Problema y usuario · 40 s
"La Dirección de Tecnología revisa hoy los logs del firewall de forma ocasional y
manual. No hay un proceso continuo ni una evaluación de vulnerabilidades. Sin eso,
cualquier plan de hardening se apoya en suposiciones."

Dato de apoyo: ${numero(st.eventos.length)} eventos en un solo día. Nadie los
revisa a mano todos los días.

## 2. Demostración · 90 s
Abrir el tablero. Señalar las tarjetas: ${numero(st.eventos.length)} eventos →
${st.alertas.length} alertas.

"De ${st.alertas.length} alertas, ${descartadas} se descartan solas."
→ Ir a **Correlación** y activar el interruptor.
"Estas tres de las 2 de la mañana tienen un mantenimiento aprobado detrás.
El sistema las cierra con justificación trazable, no las borra."

Luego señalar el contraste:
"Pero esta otra ocurre a la misma hora y NO se descarta. El cambio autorizado
dice expresamente que no autoriza envío externo de datos, y aquí hay
${bytes((st.alertas.find(a => a.tipo === 'Volumen para revisión') || {}).evento?.bytes || 0)}
saliendo hacia una dirección que no está en el inventario. La hora coincide;
el permiso no."

→ Clic en **Evidencia**. "Un clic desde la alerta hasta el registro crudo."

## 3. Prioridades · 60 s
Ir a **Hardening**. "Priorizamos con impacto por exposición, la escala del curso.
No es CVSS y lo decimos de frente."

Mover un deslizador: "si la Dirección valora distinto la exposición, el orden se
recalcula y el argumento queda a la vista."

Mostrar la ficha de la regla abierta hacia la base de datos: evidencia, cambio
propuesto, responsable por rol, efecto en la operación, validación y reversión.
"No proponemos bloquear todo. Proponemos un permiso específico, con registro, y
con un plan de vuelta atrás."

## 4. Prueba realizada · 50 s
Ir a **Validación**. Ejecutar los 4 casos.
"Probamos la frontera de la regla: con 4 fallos no dispara, con 5 sí, con los
mismos 5 fallos dispersos en 12 minutos no dispara, y los 10 minutos exactos
cuentan como dentro."

Ejecutar la comparación cruzada.
"Además el motor del navegador y el de Python dan el mismo resultado, y el de
Python reproduce sin diferencias el archivo de referencia del curso."

## 5. Límites y preguntas · 40 s
"Tres límites que reconocemos:
uno, esto entrega señales, no incidentes confirmados;
dos, las actualizaciones pendientes no permiten inferir vulnerabilidades
concretas, faltan versiones y boletines;
tres, es un solo día de datos y sin identificación de usuario, así que no
podemos atribuir una IP a una persona ni hablar de tendencia.

Lo que necesitamos de la empresa: logs reales anonimizados, la política de
retención, y saber cómo se aprueban hoy las excepciones del firewall."

Cierre: "Con logs de 30 días esto deja de ser una foto y pasa a ser una línea
base. Esa es la fase dos."

---
**Recordar:** decir «datos de prueba» al empezar. Si falla la red, el tablero
funciona local. Tener el video del correo de alerta como respaldo.`;
}

const PESTANAS = [
  { id: 'canvas', nombre: 'Canvas del MVP', archivo: 'canvas_mvp.md', fn: canvas },
  { id: 'incidente', nombre: 'Ficha de incidente', archivo: 'ficha_incidente.md', fn: fichaIncidente },
  { id: 'pitch', nombre: 'Guion del pitch', archivo: 'guion_pitch.md', fn: pitch },
];

export function render(st) {
  estado = st;
  return `
  <section class="panel">
    <div class="panel-cab">
      <div>
        <h2>Entregables</h2>
        <p class="panel-sub">Se generan a partir del conjunto cargado: si cambian los datos, cambian los textos.</p>
      </div>
      <div class="acciones-doc">
        <button id="btn-copiar" class="btn btn-fantasma">Copiar</button>
        <button id="btn-descargar" class="btn btn-primario">Descargar .md</button>
      </div>
    </div>
    <div class="subpestanas" id="subpestanas">
      ${PESTANAS.map(p => `<button class="subtab" data-tab="${p.id}">${esc(p.nombre)}</button>`).join('')}
    </div>
    <pre class="documento" id="documento"></pre>
  </section>`;
}

function pintar() {
  const p = PESTANAS.find(x => x.id === activa);
  el('documento').textContent = p.fn(estado);
  el('subpestanas').querySelectorAll('.subtab').forEach(b =>
    b.classList.toggle('activa', b.getAttribute('data-tab') === activa));
}

export function montar(st) {
  estado = st;
  el('subpestanas').querySelectorAll('.subtab').forEach(b =>
    b.addEventListener('click', () => { activa = b.getAttribute('data-tab'); pintar(); }));
  el('btn-copiar').addEventListener('click', e =>
    copiar(el('documento').textContent, e.currentTarget));
  el('btn-descargar').addEventListener('click', () => {
    const p = PESTANAS.find(x => x.id === activa);
    descargar(p.archivo, el('documento').textContent, 'text/markdown');
  });
  pintar();
}
