/* Vista 2: Motor de correlacion y descarte de falsos positivos.
 *
 * Es la demostracion central para el jurado: la misma hora de la madrugada
 * produce dos desenlaces distintos segun lo que el cambio autorizado cubre.
 */
import { esc, el, hora, soloHora, numero, bytes, pill, CLASE_SEV } from '../ui.js';

let estado = null;
let correlacionActiva = true;

export function render(st) {
  estado = st;
  const c = (st.cambios_autorizados || [])[0];

  return `
  <section class="panel">
    <div class="panel-cab">
      <div>
        <h2>Correlación con cambios autorizados</h2>
        <p class="panel-sub">Una alerta fuera de horario no es un incidente si hay mantenimiento aprobado. Pero un cambio autorizado solo cubre lo que declara cubrir.</p>
      </div>
      <label class="switch">
        <input type="checkbox" id="sw-correlacion" checked>
        <span class="switch-pista"><span class="switch-bola"></span></span>
        <span class="switch-texto">Correlacionar con cambios autorizados</span>
      </label>
    </div>

    ${c ? `<div class="ficha-cambio">
      <div class="ficha-cambio-cab">
        <span class="chip chip-azul">${esc(c.cambio_id)}</span>
        <strong>${esc(c.motivo)}</strong>
      </div>
      <div class="ficha-cambio-datos">
        <div><span class="sutil">Activo</span><strong>${esc(c.activo)}</strong></div>
        <div><span class="sutil">Ventana</span><strong>${esc(soloHora(c.inicio))} – ${esc(soloHora(c.fin))}</strong></div>
        <div><span class="sutil">Origen autorizado</span><strong class="mono">${esc(c.origen_autorizado)}</strong></div>
        <div><span class="sutil">Usuario</span><strong class="mono">${esc(c.usuario_prueba)}</strong></div>
      </div>
      <div class="ficha-cambio-limite">
        <svg class="ico" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round"><circle cx="12" cy="12" r="10"/><path d="M12 8v4M12 16h.01"/></svg>
        <span>Límite declarado: <strong>${esc(c.limite)}</strong></span>
      </div>
    </div>` : ''}

    <div id="comparativa" class="comparativa"></div>
    <div id="lista-correlacion"></div>
  </section>`;
}

function tarjetaCaso(titulo, tono, alertas, explicacion) {
  const filas = alertas.map(a => `
    <li>
      <span class="mono">${esc(a.alerta_id)}</span>
      <span class="mono sutil">${esc(soloHora(a.fecha_hora))}</span>
      <span>${esc(a.tipo)}</span>
      ${a.estado === 'Descartada'
        ? pill('Descartada', CLASE_SEV['Descartada'])
        : pill(`${a.severidad_etiqueta} · ${a.severidad}`, CLASE_SEV[a.severidad_etiqueta])}
    </li>`).join('');

  return `<div class="caso caso-${tono}">
    <div class="caso-cab">
      <span class="caso-icono">${tono === 'ok' ? '✓' : '●'}</span>
      <h3>${esc(titulo)}</h3>
    </div>
    <ul class="caso-lista">${filas || '<li class="sutil">Sin alertas en este grupo.</li>'}</ul>
    <p class="caso-nota">${explicacion}</p>
  </div>`;
}

function pintar() {
  const cubiertas = estado.alertas.filter(a => a.cambio_id);
  const enVentanaNoCubiertas = estado.alertas.filter(a =>
    !a.cambio_id && a.justificacion.includes('dentro de la ventana'));

  if (!correlacionActiva) {
    const todas = estado.alertas.filter(a =>
      cubiertas.includes(a) || enVentanaNoCubiertas.includes(a));
    el('comparativa').innerHTML = tarjetaCaso(
      'Correlación desactivada',
      'aviso',
      todas,
      'Sin cruzar contra los cambios autorizados, <strong>todas</strong> las alertas de la madrugada se ven iguales. ' +
      'Un analista tendría que revisarlas una por una. Activa el interruptor para ver la diferencia.'
    );
    el('lista-correlacion').innerHTML = '';
    return;
  }

  el('comparativa').innerHTML =
    tarjetaCaso(
      'Descartadas: actividad autorizada',
      'ok',
      cubiertas,
      'Coinciden en ventana, activo, origen autorizado y usuario con el cambio aprobado. ' +
      'Se cierran con justificación trazable, no se borran.'
    ) +
    tarjetaCaso(
      'Posible incidente: dentro de la ventana, fuera del permiso',
      'critico',
      enVentanaNoCubiertas,
      'Ocurren en el mismo rango horario, pero el cambio <strong>no autoriza envío externo de datos</strong>. ' +
      'Además el origen no es el autorizado. La coincidencia de hora no es una autorización.'
    );

  const foco = enVentanaNoCubiertas[0];
  if (!foco || !foco.evento) { el('lista-correlacion').innerHTML = ''; return; }
  const e = foco.evento;

  el('lista-correlacion').innerHTML = `
    <div class="foco">
      <h3>Por qué ${esc(e.evento_id)} no queda cubierto</h3>
      <table class="tabla tabla-comparacion">
        <thead><tr><th>Criterio</th><th>Exige el cambio</th><th>Trae el evento</th><th></th></tr></thead>
        <tbody>
          ${filaComparacion('Ventana horaria', '02:00 – 02:30', soloHora(e.fecha_hora), true)}
          ${filaComparacion('Origen autorizado', '10.60.0.20 (ADMIN-LAB)', e.origen_ip, e.origen_ip === '10.60.0.20')}
          ${filaComparacion('Usuario', 'admin_prueba', e.usuario_prueba, e.usuario_prueba === 'admin_prueba')}
          ${filaComparacion('Destino', 'BACKUP-LAB (interno)', e.destino_ip + ' (externo)', false)}
          ${filaComparacion('Volumen', 'No aplica al permiso', bytes(e.bytes), false)}
        </tbody>
      </table>
      <p class="nota">
        Coincide únicamente la hora. El cambio ampara una revisión de copia <em>hacia</em> el servidor de respaldo,
        no una transferencia de ${esc(bytes(e.bytes))} <em>desde</em> ese servidor hacia Internet.
        Esto amerita abrir una ficha de incidente; <strong>no demuestra</strong> que haya habido extracción de información.
      </p>
    </div>`;
}

function filaComparacion(criterio, exige, trae, ok) {
  return `<tr>
    <td>${esc(criterio)}</td>
    <td class="mono sutil">${esc(exige)}</td>
    <td class="mono">${esc(trae)}</td>
    <td>${ok ? '<span class="estado-ok">coincide</span>' : '<span class="estado-abierta">no coincide</span>'}</td>
  </tr>`;
}

export function montar(st) {
  estado = st;
  el('sw-correlacion').addEventListener('change', e => {
    correlacionActiva = e.target.checked;
    pintar();
  });
  pintar();
}
