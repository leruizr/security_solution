/* Vista 1: Dashboard y monitor de eventos (SOC view). */
import { esc, el, hora, numero, bytes, pill, tarjeta, abrirModal, tablaClaveValor, CLASE_SEV } from '../ui.js';
import { leerArchivo } from '../ingesta.js';

let estado = null;
let filtros = { texto: '', severidad: '', tipo: '', estado: '' };

export function render(st) {
  estado = st;
  return `
  ${panelIngesta()}
  <section class="kpis" id="kpis"></section>
  <section class="panel">
    <div class="panel-cab">
      <div>
        <h2>Eventos y alertas</h2>
        <p class="panel-sub">Un <strong>evento</strong> es un registro crudo. Una <strong>alerta</strong> es el disparo de una regla. Un <strong>incidente</strong> solo existe tras revisión humana.</p>
      </div>
    </div>
    <div class="filtros">
      <input id="f-texto" type="search" placeholder="Buscar IP, usuario, activo, regla…" autocomplete="off">
      <select id="f-sev"><option value="">Toda severidad</option></select>
      <select id="f-tipo"><option value="">Todo tipo de alerta</option></select>
      <select id="f-estado">
        <option value="">Todo estado</option>
        <option value="Abierta">Abierta</option>
        <option value="Descartada">Descartada por cambio autorizado</option>
      </select>
    </div>
    <div class="tabla-env">
      <table class="tabla">
        <thead><tr>
          <th>Alerta</th><th>Evento</th><th>Fecha y hora</th><th>Tipo</th>
          <th>Activo</th><th>Severidad</th><th>Estado</th><th></th>
        </tr></thead>
        <tbody id="tbody-alertas"></tbody>
      </table>
    </div>
    <p class="nota" id="conteo"></p>
  </section>

  <section class="panel">
    <div class="panel-cab"><h2>Eventos crudos</h2></div>
    <div class="filtros">
      <input id="f-evt" type="search" placeholder="Filtrar eventos por IP, usuario, regla o acción…" autocomplete="off">
    </div>
    <div class="tabla-env tabla-alta">
      <table class="tabla tabla-compacta">
        <thead><tr>
          <th>ID</th><th>Fecha y hora</th><th>Tipo</th><th>Origen</th><th>Destino</th>
          <th>Puerto</th><th>Acción</th><th>Regla</th><th>Usuario</th><th>Resultado</th><th class="num">Bytes</th>
        </tr></thead>
        <tbody id="tbody-eventos"></tbody>
      </table>
    </div>
    <p class="nota" id="conteo-evt"></p>
  </section>`;
}

function panelIngesta() {
  return `
  <section class="panel panel-ingesta">
    <div class="ingesta">
      <div class="ingesta-rapida">
        <h2>Origen de datos</h2>
        <p class="panel-sub">El análisis corre completo en tu navegador. Ningún archivo se envía a un servidor.</p>
        <button id="btn-demo" class="btn btn-primario">
          <svg class="ico" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><path d="M13 2 3 14h9l-1 8 10-12h-9z"/></svg>
          Cargar dataset de prueba (324 eventos)
        </button>
        <div id="badge-dataset" class="badge-dataset"></div>
      </div>
      <div class="ingesta-archivo">
        <div id="zona-drop" class="dropzone" tabindex="0" role="button" aria-label="Importar archivo de logs">
          <svg class="ico-grande" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.5" stroke-linecap="round" stroke-linejoin="round"><path d="M21 15v4a2 2 0 0 1-2 2H5a2 2 0 0 1-2-2v-4"/><path d="M7 10l5-5 5 5"/><path d="M12 5v12"/></svg>
          <strong>Importar logs propios</strong>
          <span>Arrastra aquí un <code>.csv</code>, <code>.json</code> o <code>.jsonl</code>, o haz clic para elegirlo</span>
          <input id="input-archivo" type="file" accept=".csv,.json,.jsonl,.ndjson" hidden>
        </div>
        <div id="estado-ingesta" class="estado-ingesta"></div>
      </div>
    </div>
  </section>`;
}

/* ---------------------------------------------------------------- */

function kpis() {
  const a = estado.alertas;
  const abiertas = a.filter(x => x.estado === 'Abierta');
  const criticas = abiertas.filter(x => x.severidad_etiqueta === 'Crítica');
  const descartadas = a.filter(x => x.estado === 'Descartada');
  const altos = (estado.hallazgos || []).filter(h => (h.impacto * h.exposicion) >= 6);

  el('kpis').innerHTML =
    tarjeta({ cifra: numero(estado.eventos.length), etiqueta: 'Eventos analizados' }) +
    tarjeta({ cifra: a.length, etiqueta: 'Alertas generadas', detalle: `${abiertas.length} abiertas · ${descartadas.length} descartadas` }) +
    tarjeta({ cifra: criticas.length, etiqueta: 'Alertas críticas abiertas', tono: criticas.length ? 'critico' : 'ok', detalle: 'Severidad 9' }) +
    tarjeta({ cifra: (estado.cambios_autorizados || []).length, etiqueta: 'Cambios autorizados vigentes', detalle: (estado.cambios_autorizados || []).map(c => c.cambio_id).join(', ') || '—' }) +
    tarjeta({ cifra: altos.length, etiqueta: 'Hallazgos de prioridad alta', tono: 'aviso', detalle: 'Puntaje 6 a 9' });
}

function opciones(sel, valores) {
  const s = el(sel);
  const actual = s.value;
  s.innerHTML = s.options[0].outerHTML +
    valores.map(v => `<option value="${esc(v)}">${esc(v)}</option>`).join('');
  s.value = actual;
}

function alertasFiltradas() {
  const q = filtros.texto.toLowerCase();
  return estado.alertas.filter(a => {
    if (filtros.severidad && a.severidad_etiqueta !== filtros.severidad) return false;
    if (filtros.tipo && a.tipo !== filtros.tipo) return false;
    if (filtros.estado && a.estado !== filtros.estado) return false;
    if (!q) return true;
    const e = a.evento || {};
    return [a.alerta_id, a.evento_id, a.tipo, a.motivo, a.activo, a.zona,
            e.origen_ip, e.destino_ip, e.usuario_prueba, e.regla_id]
      .join(' ').toLowerCase().includes(q);
  });
}

function pintarAlertas() {
  const filas = alertasFiltradas();
  const tb = el('tbody-alertas');

  if (!filas.length) {
    tb.innerHTML = '<tr><td colspan="8" class="vacio">Sin alertas para este filtro.</td></tr>';
  } else {
    tb.innerHTML = filas.map(a => {
      const sev = a.estado === 'Descartada'
        ? pill('Descartada', CLASE_SEV['Descartada'])
        : pill(`${a.severidad_etiqueta} · ${a.severidad}`, CLASE_SEV[a.severidad_etiqueta]);
      const est = a.estado === 'Descartada'
        ? `<span class="estado estado-ok">✓ Cambio ${esc(a.cambio_id)}</span>`
        : '<span class="estado estado-abierta">● Abierta</span>';
      return `<tr>
        <td class="mono">${esc(a.alerta_id)}</td>
        <td class="mono">${esc(a.evento_id)}</td>
        <td class="mono nowrap">${esc(hora(a.fecha_hora))}</td>
        <td>${esc(a.tipo)}</td>
        <td><strong>${esc(a.activo)}</strong><br><span class="sutil">${esc(a.zona)} · ${esc(a.criticidad)}</span></td>
        <td>${sev}</td>
        <td>${est}</td>
        <td><button class="btn btn-mini" data-ver="${esc(a.alerta_id)}">Evidencia</button></td>
      </tr>`;
    }).join('');
  }

  el('conteo').textContent =
    `Mostrando ${filas.length} de ${estado.alertas.length} alertas. ` +
    'Una alerta es una señal para revisión: no equivale a un incidente confirmado.';

  tb.querySelectorAll('[data-ver]').forEach(b =>
    b.addEventListener('click', () => verEvidencia(b.getAttribute('data-ver'))));
}

function pintarEventos() {
  const q = (el('f-evt').value || '').trim().toLowerCase();
  const filas = estado.eventos.filter(e => !q ||
    [e.evento_id, e.origen_ip, e.destino_ip, e.usuario_prueba, e.regla_id, e.accion, e.tipo, e.resultado]
      .join(' ').toLowerCase().includes(q));

  const limite = 150;
  el('tbody-eventos').innerHTML = filas.slice(0, limite).map(e => `<tr>
      <td class="mono">${esc(e.evento_id)}</td>
      <td class="mono nowrap">${esc(hora(e.fecha_hora))}</td>
      <td>${esc(e.tipo)}</td>
      <td class="mono">${esc(e.origen_ip)}</td>
      <td class="mono">${esc(e.destino_ip)}</td>
      <td class="mono">${esc(e.puerto_destino)}</td>
      <td>${e.accion === 'deny' ? '<span class="deny">deny</span>' : esc(e.accion)}</td>
      <td class="mono">${esc(e.regla_id)}</td>
      <td>${esc(e.usuario_prueba)}</td>
      <td>${e.resultado === 'fallo' ? '<span class="fallo">fallo</span>' : esc(e.resultado)}</td>
      <td class="num mono">${esc(bytes(e.bytes))}</td>
    </tr>`).join('');

  el('conteo-evt').textContent = filas.length > limite
    ? `Mostrando los primeros ${limite} de ${filas.length} eventos. Afina el filtro para ver el resto.`
    : `${filas.length} eventos.`;
}

function verEvidencia(alertaId) {
  const a = estado.alertas.find(x => x.alerta_id === alertaId);
  if (!a) return;
  const e = a.evento;

  let html = `<p class="motivo">${esc(a.motivo)}</p>`;

  html += `<div class="bloque ${a.estado === 'Descartada' ? 'bloque-ok' : 'bloque-aviso'}">
    <strong>${a.estado === 'Descartada' ? '✓ Falso positivo descartado' : '● Requiere revisión'}</strong>
    <p>${esc(a.justificacion)}</p></div>`;

  if (a.estado !== 'Descartada') {
    html += `<div class="bloque">
      <strong>Cálculo de severidad</strong>
      <p>criticidad de ${esc(a.activo)} (${esc(a.criticidad)} = ${a.severidad / a.peso_senal})
         × peso de la señal (${a.peso_senal}) = <strong>${a.severidad}</strong> · ${esc(a.severidad_etiqueta)}</p>
    </div>`;
  }

  if (a.notas.length) {
    html += '<div class="bloque"><strong>Observaciones</strong><ul>' +
      a.notas.map(n => `<li>${esc(n)}</li>`).join('') + '</ul></div>';
  }

  if (e) {
    html += '<h4>Evento que originó la alerta</h4>' + tablaClaveValor({
      evento_id: e.evento_id, fecha_hora: hora(e.fecha_hora), tipo: e.tipo,
      origen_ip: e.origen_ip, destino_ip: e.destino_ip, puerto_destino: e.puerto_destino,
      accion: e.accion, regla_id: e.regla_id, usuario_prueba: e.usuario_prueba,
      resultado: e.resultado, bytes: `${numero(e.bytes)} (${bytes(e.bytes)})`,
    });
  }

  html += `<p class="nota">Disposición: ${esc(a.disposicion)}</p>`;
  abrirModal(`${a.alerta_id} · ${a.tipo}`, html);
}

/* ---------------------------------------------------------------- */

function mensajeIngesta(tipo, texto) {
  el('estado-ingesta').innerHTML = `<div class="msg msg-${tipo}">${esc(texto)}</div>`;
}

function badgeDataset() {
  el('badge-dataset').innerHTML =
    `<span class="chip">Dataset activo: ${esc(estado.nombre_dataset)} · ${numero(estado.eventos.length)} logs</span>`;
}

export function montar(st, recalcular) {
  estado = st;

  opciones('f-sev', ['Crítica', 'Alta', 'Media', 'Baja', 'Descartada']);
  opciones('f-tipo', [...new Set(estado.alertas.map(a => a.tipo))].sort());

  el('f-texto').addEventListener('input', e => { filtros.texto = e.target.value; pintarAlertas(); });
  el('f-sev').addEventListener('change', e => { filtros.severidad = e.target.value; pintarAlertas(); });
  el('f-tipo').addEventListener('change', e => { filtros.tipo = e.target.value; pintarAlertas(); });
  el('f-estado').addEventListener('change', e => { filtros.estado = e.target.value; pintarAlertas(); });
  el('f-evt').addEventListener('input', pintarEventos);

  el('btn-demo').addEventListener('click', () => {
    const t0 = performance.now();
    recalcular(null);
    mensajeIngesta('ok', `✓ Dataset oficial recargado y reglas ejecutadas en ${Math.max(1, Math.round(performance.now() - t0))} ms.`);
  });

  const zona = el('zona-drop');
  const input = el('input-archivo');

  const procesar = (file) => {
    if (!file) return;
    mensajeIngesta('info', `Leyendo ${file.name}…`);
    leerArchivo(file)
      .then(eventos => {
        recalcular({ eventos, nombre: file.name });
        mensajeIngesta('ok', `✓ Se cargaron ${numero(eventos.length)} eventos correctamente desde ${file.name}.`);
      })
      .catch(err => mensajeIngesta('error', err.message));
  };

  zona.addEventListener('click', () => input.click());
  zona.addEventListener('keydown', e => {
    if (e.key === 'Enter' || e.key === ' ') { e.preventDefault(); input.click(); }
  });
  input.addEventListener('change', e => procesar(e.target.files[0]));
  ['dragenter', 'dragover'].forEach(ev => zona.addEventListener(ev, e => {
    e.preventDefault(); zona.classList.add('activa');
  }));
  ['dragleave', 'drop'].forEach(ev => zona.addEventListener(ev, e => {
    e.preventDefault(); zona.classList.remove('activa');
  }));
  zona.addEventListener('drop', e => procesar(e.dataTransfer.files[0]));

  kpis(); badgeDataset(); pintarAlertas(); pintarEventos();
}
