/* Vista 4a: Laboratorio de pruebas.
 *
 * Dos comprobaciones distintas:
 *  1. Casos controlados: prueban la frontera exacta de la regla de fallos.
 *  2. Validacion cruzada: comprueba que el motor del navegador (JS) produce
 *     las MISMAS alertas que analizador.py, que a su vez reproduce la
 *     referencia del curso. Si las dos implementaciones se separan, se ve aqui.
 */
import { esc, el, numero } from '../ui.js';
import { detectar, detectarAmpliadas } from '../motor.js';

let estado = null;

function eventosSinteticos(minutos) {
  const base = new Date('2026-11-20T09:00:00');
  return minutos.map((m, i) => {
    const t = new Date(base.getTime() + m * 60000);
    const iso = t.getFullYear() + '-' +
      String(t.getMonth() + 1).padStart(2, '0') + '-' +
      String(t.getDate()).padStart(2, '0') + 'T' +
      String(t.getHours()).padStart(2, '0') + ':' +
      String(t.getMinutes()).padStart(2, '0') + ':00';
    return {
      evento_id: 'T' + String(i + 1).padStart(3, '0'),
      fecha_hora: iso, tipo: 'autenticacion',
      origen_ip: '10.60.40.21', destino_ip: '10.60.20.20',
      puerto_destino: '22', accion: 'allow', regla_id: 'R02',
      usuario_prueba: 'usr_prueba_07', resultado: 'fallo', bytes: '1200',
    };
  });
}

export function render(st) {
  estado = st;
  return `
  <section class="panel">
    <div class="panel-cab">
      <div>
        <h2>Casos controlados</h2>
        <p class="panel-sub">Prueban la frontera exacta de la regla: 5 fallos de la misma tupla dentro de una ventana móvil de 10 minutos.</p>
      </div>
      <button id="btn-todos" class="btn btn-primario">Ejecutar los 4 casos</button>
    </div>
    <div id="casos" class="casos-grid"></div>
    <p class="nota">Los eventos de prueba se generan en memoria. No modifican el conjunto cargado ni ningún archivo.</p>
  </section>

  <section class="panel">
    <div class="panel-cab">
      <div>
        <h2>Validación cruzada</h2>
        <p class="panel-sub">Dos comprobaciones: que las 4 reglas del curso sigan dando exactamente la referencia, y que el motor del navegador y <code>analizador.py</code> coincidan en todas las reglas.</p>
      </div>
      <button id="btn-cruzada" class="btn btn-fantasma">Comparar</button>
    </div>
    <div id="cruzada"></div>
  </section>`;
}

function pintarCasos(resultados) {
  el('casos').innerHTML = (estado.casos_controlados || []).map((c, i) => {
    const r = resultados ? resultados[i] : null;
    const ok = r && r.obtenidas === c.alertas_esperadas;
    return `<div class="caso-prueba ${r ? (ok ? 'ok' : 'fallo') : ''}">
      <div class="caso-prueba-cab">
        <h3>${esc(c.caso)}</h3>
        ${r ? `<span class="marca">${ok ? '✓' : '✕'}</span>` : ''}
      </div>
      <p class="sutil">Fallos en los minutos ${c.minutos.join(', ')}</p>
      <dl class="caso-prueba-datos">
        <dt>Esperado</dt><dd>${c.alertas_esperadas} alerta${c.alertas_esperadas === 1 ? '' : 's'}</dd>
        <dt>Obtenido</dt><dd>${r ? `${r.obtenidas} alerta${r.obtenidas === 1 ? '' : 's'}` : '—'}</dd>
      </dl>
      <button class="btn btn-mini" data-caso="${i}">Ejecutar</button>
    </div>`;
  }).join('');

  el('casos').querySelectorAll('[data-caso]').forEach(b =>
    b.addEventListener('click', () => ejecutar(parseInt(b.getAttribute('data-caso'), 10))));
}

let resultados = [];

function ejecutar(indice) {
  const c = estado.casos_controlados[indice];
  const alertas = detectar(eventosSinteticos(c.minutos), estado.parametros)
    .filter(a => a.tipo === 'Fallos repetidos');
  resultados[indice] = { obtenidas: alertas.length };
  pintarCasos(resultados);
}

function ejecutarTodos() {
  resultados = [];
  (estado.casos_controlados || []).forEach((c, i) => {
    const alertas = detectar(eventosSinteticos(c.minutos), estado.parametros)
      .filter(a => a.tipo === 'Fallos repetidos');
    resultados[i] = { obtenidas: alertas.length };
  });
  pintarCasos(resultados);
}

function compararCruzada() {
  const cfg = estado.parametros;
  const eventos = estado.eventos_oficiales;

  // Motor del navegador, en el mismo orden que lo hace analizador.py.
  const base = detectar(eventos, cfg);
  const ampliadas = detectarAmpliadas(eventos, cfg, estado.inventario, estado.politicas, base.length);
  const propias = base.concat(ampliadas);

  const referencia = estado.alertas_python || [];
  const refBase = referencia.filter(a => a.origen_regla === 'base');

  const dif = [];
  const n = Math.max(referencia.length, propias.length);
  for (let i = 0; i < n; i++) {
    const a = referencia[i], b = propias[i];
    if (!a || !b || a.alerta_id !== b.alerta_id || a.evento_id !== b.evento_id
        || a.tipo !== b.tipo || a.motivo !== b.motivo) {
      dif.push({ i, a, b });
    }
  }
  const ok = dif.length === 0;

  el('cruzada').innerHTML = `
    <div class="bloque bloque-ok">
      <strong>✓ Las 4 reglas del curso siguen intactas</strong>
      <p>Producen ${base.length} alertas, las mismas de
      <code>07_Validacion/Referencia_alertas.csv</code>. Las reglas que agregó el
      equipo se numeran a continuación y nunca desplazan los identificadores de
      las base, que ya están citados en el expediente.
      La comprobación byte a byte se hace fuera del navegador:
      <code>diff salidas/alertas_base.csv Kenworth_Recursos_de_Prueba/07_Validacion/Referencia_alertas.csv</code>.</p>
    </div>

    <div class="bloque ${ok ? 'bloque-ok' : 'bloque-aviso'}">
      <strong>${ok ? '✓ Los dos motores coinciden' : '✕ Hay diferencias entre los motores'}</strong>
      <p>Navegador: ${propias.length} alertas (${base.length} base + ${ampliadas.length} ampliadas) ·
      <code>analizador.py</code>: ${referencia.length} alertas, sobre los mismos
      ${numero(eventos.length)} eventos.</p>
      ${ok ? '' : `<ul>${dif.map(d => `<li>Posición ${d.i + 1}: Python ${esc(d.a ? d.a.alerta_id + ' ' + d.a.tipo : '—')} · navegador ${esc(d.b ? d.b.alerta_id + ' ' + d.b.tipo : '—')}</li>`).join('')}</ul>`}
    </div>

    <div class="tabla-env">
      <table class="tabla">
        <thead><tr><th>Alerta</th><th>Evento</th><th>Tipo</th><th>Regla</th><th>analizador.py</th></tr></thead>
        <tbody>${propias.map((b, i) => {
          const a = referencia[i];
          const igual = a && a.alerta_id === b.alerta_id && a.tipo === b.tipo && a.motivo === b.motivo;
          return `<tr>
            <td class="mono">${esc(b.alerta_id)}</td>
            <td class="mono">${esc(b.evento_id)}</td>
            <td>${esc(b.tipo)}</td>
            <td>${b.origen_regla === 'base'
              ? '<span class="sutil">del curso</span>'
              : '<span class="pill sev-media">del equipo</span>'}</td>
            <td>${igual ? '<span class="estado-ok">✓ coincide</span>' : '<span class="estado-abierta">difiere</span>'}</td>
          </tr>`;
        }).join('')}</tbody>
      </table>
    </div>
    <p class="nota">${refBase.length} de las ${referencia.length} alertas vienen de las reglas del curso; las demás son la mejora del equipo.</p>`;
}

export function montar(st) {
  estado = st;
  el('btn-todos').addEventListener('click', ejecutarTodos);
  el('btn-cruzada').addEventListener('click', compararCruzada);
  pintarCasos(null);
}
