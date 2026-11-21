/* Vista 0: Panorama. Las metricas del conjunto, para entenderlo de un vistazo.
 *
 * Reglas de visualizacion que se siguen aqui:
 *  - Una sola serie por grafico, en un unico tono azul (#3987e5). Validado
 *    sobre la superficie oscura: banda de luminosidad, croma y contraste 4.98:1.
 *  - Los colores de estado (critico, advertencia, correcto) son los reservados
 *    del sistema y NUNCA van solos: siempre con icono y texto, porque rojo y
 *    verde se confunden con daltonismo.
 *  - Todo valor se puede leer como numero, no solo como tamano de barra.
 */
import { esc, el, numero, bytes } from '../ui.js';

let estado = null;

const AZUL = '#3987e5';
const EST = {
  critico: { color: '#d03b3b', icono: '●', nombre: 'Crítica' },
  aviso:   { color: '#fab219', icono: '▲', nombre: 'Alta' },
  medio:   { color: '#3987e5', icono: '◆', nombre: 'Media' },
  bueno:   { color: '#0ca30c', icono: '✓', nombre: 'Descartada' },
};

/* ---------------------------------------------------------------- */
/* Calculos                                                          */
/* ---------------------------------------------------------------- */

function porHora(eventos, alertas) {
  const horas = [];
  for (let h = 0; h < 24; h++) horas.push({ hora: h, eventos: 0, alertas: 0 });
  eventos.forEach(e => {
    const h = parseInt(String(e.fecha_hora).slice(11, 13), 10);
    if (!isNaN(h)) horas[h].eventos++;
  });
  alertas.forEach(a => {
    const h = parseInt(String(a.fecha_hora).slice(11, 13), 10);
    if (!isNaN(h)) horas[h].alertas++;
  });
  return horas;
}

function porRegla(eventos, politicas) {
  const cuenta = {};
  eventos.forEach(e => { cuenta[e.regla_id] = (cuenta[e.regla_id] || 0) + 1; });
  return Object.keys(cuenta).map(id => {
    const p = (politicas || []).find(x => x.regla_id === id);
    return {
      id,
      total: cuenta[id],
      registro: p ? p.registro : '?',
      detalle: p ? `${p.origen} → ${p.destino} · ${p.servicio} · ${p.accion}` : 'Sin política asociada',
    };
  }).sort((a, b) => b.total - a.total);
}

function volumenPorDestino(eventos, inventario) {
  const porIp = new Map((inventario || []).map(a => [a.ip_prueba, a]));
  const cuenta = {};
  eventos.forEach(e => {
    const b = parseInt(e.bytes, 10) || 0;
    if (!cuenta[e.destino_ip]) cuenta[e.destino_ip] = { ip: e.destino_ip, bytes: 0, eventos: 0 };
    cuenta[e.destino_ip].bytes += b;
    cuenta[e.destino_ip].eventos++;
  });
  return Object.keys(cuenta).map(ip => {
    const a = porIp.get(ip);
    return { ...cuenta[ip], nombre: a ? a.nombre_prueba : null, externo: !a };
  }).sort((a, b) => b.bytes - a.bytes).slice(0, 6);
}

function severidades(alertas) {
  const g = { Crítica: 0, Alta: 0, Media: 0, Baja: 0, Descartada: 0 };
  alertas.forEach(a => { g[a.severidad_etiqueta] = (g[a.severidad_etiqueta] || 0) + 1; });
  return [
    { ...EST.critico, n: g['Crítica'] },
    { ...EST.aviso, n: g['Alta'] },
    { ...EST.medio, n: g['Media'] + g['Baja'] },
    { ...EST.bueno, n: g['Descartada'] },
  ];
}

/* ---------------------------------------------------------------- */
/* Graficos                                                          */
/* ---------------------------------------------------------------- */

/* Columnas de una sola serie. El valor se lee al pasar el cursor y la
   tabla de abajo lo deja disponible sin color ni interaccion. */
function columnasPorHora(datos) {
  const max = Math.max(1, ...datos.map(d => d.eventos));
  const W = 740, H = 180, PAD_I = 34, PAD_D = 8, PAD_S = 14, PAD_B = 26;
  const util = W - PAD_I - PAD_D;
  const alto = H - PAD_S - PAD_B;
  const paso = util / 24;
  const ancho = paso - 2;                       // separacion de 2px entre barras

  const rejilla = [0, 0.5, 1].map(f => {
    const y = PAD_S + alto - alto * f;
    return `<line x1="${PAD_I}" y1="${y}" x2="${W - PAD_D}" y2="${y}" class="rejilla"/>
            <text x="${PAD_I - 7}" y="${y + 4}" class="eje eje-num">${Math.round(max * f)}</text>`;
  }).join('');

  const barras = datos.map(d => {
    const h = d.eventos === 0 ? 0 : Math.max(2, (d.eventos / max) * alto);
    const x = PAD_I + d.hora * paso + 1;
    const y = PAD_S + alto - h;
    const etq = String(d.hora).padStart(2, '0') + ':00';
    const marca = d.alertas
      ? `<circle cx="${x + ancho / 2}" cy="${y - 7}" r="3.5" fill="${EST.critico.color}"/>`
      : '';
    return `<g class="col">
      <title>${etq} · ${d.eventos} eventos${d.alertas ? ' · ' + d.alertas + ' alerta(s)' : ''}</title>
      <rect x="${x}" y="${PAD_S}" width="${ancho}" height="${alto}" class="col-zona"/>
      ${h ? `<rect x="${x}" y="${y}" width="${ancho}" height="${h}" rx="3" fill="${AZUL}"/>` : ''}
      ${marca}
    </g>`;
  }).join('');

  const etiquetas = datos.filter(d => d.hora % 3 === 0).map(d =>
    `<text x="${PAD_I + d.hora * paso + ancho / 2}" y="${H - 8}" class="eje" text-anchor="middle">${String(d.hora).padStart(2, '0')}</text>`
  ).join('');

  return `<svg viewBox="0 0 ${W} ${H}" class="grafico" role="img"
      aria-label="Eventos por hora del día. Máximo ${max} eventos.">
    ${rejilla}${barras}${etiquetas}
  </svg>
  <p class="leyenda-pie">
    <span class="punto" style="background:${EST.critico.color}"></span>
    Hora con alertas generadas · pasa el cursor sobre una barra para ver el detalle
  </p>`;
}

/* Barras horizontales de una sola serie, con el numero siempre visible. */
function barrasHorizontales(filas, opciones) {
  const o = opciones || {};
  const max = Math.max(1, ...filas.map(f => f.valor));
  return `<div class="barras">${filas.map(f => `
    <div class="barra-fila">
      <div class="barra-nombre">
        ${f.insignia ? `<span class="insignia">${esc(f.insignia)}</span>` : ''}
        <strong>${esc(f.nombre)}</strong>
        ${f.detalle ? `<span class="barra-detalle">${esc(f.detalle)}</span>` : ''}
      </div>
      <div class="barra-pista" title="${esc(f.titulo || (f.nombre + ': ' + f.texto))}">
        <div class="barra-relleno" style="width:${Math.max(1.5, (f.valor / max) * 100)}%;background:${f.color || AZUL}"></div>
      </div>
      <div class="barra-valor">${esc(f.texto)}</div>
    </div>`).join('')}</div>
  ${o.nota ? `<p class="nota">${o.nota}</p>` : ''}`;
}

function listaSeveridad(grupos) {
  const max = Math.max(1, ...grupos.map(g => g.n));
  return `<div class="barras">${grupos.map(g => `
    <div class="barra-fila">
      <div class="barra-nombre">
        <span class="icono-estado" style="color:${g.color}" aria-hidden="true">${g.icono}</span>
        <strong>${esc(g.nombre)}</strong>
      </div>
      <div class="barra-pista">
        ${g.n ? `<div class="barra-relleno" style="width:${Math.max(2, (g.n / max) * 100)}%;background:${g.color}"></div>` : ''}
      </div>
      <div class="barra-valor">${g.n}</div>
    </div>`).join('')}</div>`;
}

function matrizServidores(servidores) {
  const nombres = Object.keys(servidores || {});
  if (!nombres.length) return '<p class="nota">Sin información de configuración.</p>';

  const controles = [
    { k: 'mfa_administracion', n: 'MFA administrativo', bueno: v => v === true },
    { k: 'registro_centralizado', n: 'Registro centralizado', bueno: v => v === true },
    { k: 'cuentas_compartidas', n: 'Sin cuentas compartidas', bueno: v => v === false },
    { k: 'administracion_restringida', n: 'Administración restringida', bueno: v => v === true },
    { k: 'actualizaciones_pendientes', n: 'Actualizaciones al día', bueno: v => v === 0 },
    { k: 'respaldo_ultima_prueba', n: 'Restauración probada', bueno: v => v !== 'No registrada' },
  ];

  const celda = (ok, texto) => {
    const e = ok ? EST.bueno : EST.critico;
    return `<td><span class="estado-celda" style="color:${e.color}">
      <span aria-hidden="true">${ok ? '✓' : '✕'}</span> ${esc(texto)}</span></td>`;
  };

  const filas = controles.map(c => `<tr>
    <th scope="row">${esc(c.n)}</th>
    ${nombres.map(n => {
      const v = servidores[n][c.k];
      const ok = c.bueno(v);
      let texto;
      if (c.k === 'actualizaciones_pendientes') texto = ok ? 'Sí' : `${v} pendiente${v === 1 ? '' : 's'}`;
      else if (c.k === 'respaldo_ultima_prueba') texto = ok ? String(v) : 'No registrada';
      else texto = ok ? 'Sí' : 'No';
      return celda(ok, texto);
    }).join('')}
  </tr>`).join('');

  return `<div class="tabla-env"><table class="tabla matriz">
    <thead><tr><th>Control</th>${nombres.map(n => `<th>${esc(n)}</th>`).join('')}</tr></thead>
    <tbody>${filas}</tbody>
  </table></div>
  <p class="nota">«No registrada» significa ausencia de evidencia, no que el respaldo no exista. Las actualizaciones pendientes no permiten inferir una vulnerabilidad concreta.</p>`;
}

/* ---------------------------------------------------------------- */

export function render(st) {
  estado = st;
  return `
  <section class="panel panel-hero">
    <div class="hero">
      <div class="hero-cifra" id="hero-cifra">—</div>
      <div class="hero-texto">
        <strong id="hero-titulo">—</strong>
        <p id="hero-sub" class="panel-sub"></p>
      </div>
    </div>
    <div class="kpis-linea" id="kpis-linea"></div>
  </section>

  <section class="panel">
    <div class="panel-cab"><div>
      <h2>Actividad por hora</h2>
      <p class="panel-sub">Dónde se concentra el tráfico y en qué horas se generaron alertas. El horario habitual de prueba es de 07:00 a 19:00.</p>
    </div></div>
    <div id="g-horas"></div>
    <details class="tabla-alterna">
      <summary>Ver los datos en tabla</summary>
      <div id="t-horas"></div>
    </details>
  </section>

  <div class="rejilla-2">
    <section class="panel">
      <div class="panel-cab"><div>
        <h2>Alertas por severidad</h2>
        <p class="panel-sub">Severidad = criticidad del activo × peso de la señal.</p>
      </div></div>
      <div id="g-severidad"></div>
    </section>

    <section class="panel">
      <div class="panel-cab"><div>
        <h2>Tráfico por regla del firewall</h2>
        <p class="panel-sub">Qué regla autorizó cada evento, y cuáles no dejan registro.</p>
      </div></div>
      <div id="g-reglas"></div>
    </section>
  </div>

  <section class="panel">
    <div class="panel-cab"><div>
      <h2>Volumen por destino</h2>
      <p class="panel-sub">Suma de bytes observados. Los destinos que no están en el inventario son salidas hacia Internet.</p>
    </div></div>
    <div id="g-volumen"></div>
  </section>

  <section class="panel">
    <div class="panel-cab"><div>
      <h2>Estado de configuración de los servidores</h2>
      <p class="panel-sub">De dónde salen los hallazgos de hardening. Cada casilla indica si el control está o no en su lugar.</p>
    </div></div>
    <div id="t-servidores"></div>
  </section>`;
}

export function montar(st) {
  estado = st;
  const ev = estado.eventos;
  const al = estado.alertas;
  const abiertas = al.filter(a => a.estado === 'Abierta');
  const criticas = abiertas.filter(a => a.severidad_etiqueta === 'Crítica');
  const descartadas = al.filter(a => a.estado === 'Descartada');

  // Cifra principal: lo unico que exige accion hoy.
  el('hero-cifra').textContent = criticas.length;
  el('hero-cifra').style.color = criticas.length ? EST.critico.color : EST.bueno.color;
  el('hero-titulo').textContent = criticas.length === 1
    ? 'alerta crítica requiere revisión' : 'alertas críticas requieren revisión';
  el('hero-sub').textContent =
    `De ${numero(ev.length)} eventos analizados salieron ${al.length} alertas. ` +
    `${descartadas.length} se cerraron solas con un cambio autorizado y ` +
    `${abiertas.length} quedaron abiertas. Una alerta es una señal para revisión: no confirma un incidente.`;

  const auten = ev.filter(e => e.tipo === 'autenticacion').length;
  const denegados = ev.filter(e => e.accion === 'deny').length;
  const sinRegistro = ev.filter(e => {
    const p = (estado.politicas || []).find(x => x.regla_id === e.regla_id);
    return p && p.registro === 'no';
  }).length;

  el('kpis-linea').innerHTML = [
    { n: numero(ev.length), t: 'Eventos' },
    { n: auten, t: 'De autenticación' },
    { n: denegados, t: 'Bloqueados por el firewall' },
    { n: sinRegistro, t: 'Sin registro en la política', aviso: sinRegistro > 0 },
    { n: (estado.inventario || []).length, t: 'Activos en el inventario' },
  ].map(k => `<div class="kpi-linea${k.aviso ? ' kpi-linea-aviso' : ''}">
      <span class="kpi-linea-n">${esc(k.n)}</span>
      <span class="kpi-linea-t">${esc(k.t)}</span>
    </div>`).join('');

  // Actividad por hora
  const horas = porHora(ev, al);
  el('g-horas').innerHTML = columnasPorHora(horas);
  el('t-horas').innerHTML = `<div class="tabla-env"><table class="tabla tabla-compacta">
    <thead><tr><th>Hora</th><th class="num">Eventos</th><th class="num">Alertas</th></tr></thead>
    <tbody>${horas.filter(h => h.eventos || h.alertas).map(h =>
      `<tr><td class="mono">${String(h.hora).padStart(2, '0')}:00</td>
        <td class="num">${h.eventos}</td><td class="num">${h.alertas}</td></tr>`).join('')}
    </tbody></table></div>`;

  // Severidad
  el('g-severidad').innerHTML = listaSeveridad(severidades(al));

  // Reglas
  const reglas = porRegla(ev, estado.politicas);
  el('g-reglas').innerHTML = barrasHorizontales(reglas.map(r => ({
    nombre: r.id,
    detalle: r.detalle,
    insignia: r.registro === 'no' ? 'no registra' : null,
    valor: r.total,
    texto: numero(r.total),
    titulo: `${r.id}: ${r.total} eventos`,
  })), {
    nota: 'Una regla que no registra deja los eventos fuera de cualquier auditoría posterior, aunque los permita.',
  });

  // Volumen
  const vol = volumenPorDestino(ev, estado.inventario);
  el('g-volumen').innerHTML = barrasHorizontales(vol.map(v => ({
    nombre: v.nombre || v.ip,
    detalle: v.nombre ? `${v.ip} · ${v.eventos} eventos` : `fuera del inventario · ${v.eventos} evento(s)`,
    insignia: v.externo ? 'externo' : null,
    valor: v.bytes,
    texto: bytes(v.bytes),
    titulo: `${v.nombre || v.ip}: ${numero(v.bytes)} bytes`,
  })), {
    nota: 'Un volumen alto hacia un destino externo es una señal para investigar, no evidencia de extracción de información.',
  });

  // Servidores
  el('t-servidores').innerHTML = matrizServidores(estado.servidores);
}
