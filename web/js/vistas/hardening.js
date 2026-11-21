/* Vista 3: Matriz de vulnerabilidades y plan de hardening. */
import { esc, el, descargar } from '../ui.js';

let estado = null;

/* Puntuacion inicial propuesta por el equipo. NO viene del paquete del curso:
 * hallazgos_iniciales.csv trae impacto como texto (Alto / Medio / Por precisar)
 * y no trae exposicion. Estos numeros son nuestra valoracion y son editables,
 * que es justo lo que pide la rubrica: argumentar ambas dimensiones. */
export const SEMILLA = {
  H01: { impacto: 3, exposicion: 3 },
  H02: { impacto: 3, exposicion: 2 },
  H03: { impacto: 3, exposicion: 2 },
  H04: { impacto: 2, exposicion: 2, precisar: true },
  H05: { impacto: 3, exposicion: 2 },
  H06: { impacto: 2, exposicion: 1, precisar: true },
  H07: { impacto: 2, exposicion: 2 },
};

export const FICHAS = {
  H01: {
    titulo: 'Reemplazar la regla R02 por un permiso específico y con registro',
    activo: 'DB-LAB (10.60.20.20)',
    evidencia: 'R02 permite Usuarios → DB-LAB con servicio «any», acción allow y registro desactivado. Es una excepción sin fecha de revisión. Los eventos E0301–E0308 atraviesan esta regla.',
    cambio: 'Eliminar R02. Crear una regla que permita únicamente APP-LAB (10.60.20.10) → DB-LAB (10.60.20.20) en TCP/5432, con registro activado. La administración puntual se tramita por R03 desde ADMIN-LAB.',
    responsable: 'Administrador de redes / firewall',
    beneficio: 'Elimina el acceso directo de toda la zona de usuarios a la base de datos y recupera la trazabilidad: hoy esos accesos no quedan registrados.',
    riesgo: 'Analistas que hoy consulten la base directamente desde su equipo perderán el acceso. Hay que identificarlos antes y darles una ruta alterna.',
    validacion: 'Probar en ventana de mantenimiento: confirmar que APP-LAB sigue operando, que un equipo de la zona Usuarios ya no alcanza el puerto 5432, y que los intentos quedan registrados.',
    reversion: 'Restaurar la política anterior desde el snapshot de configuración previo al cambio. Ventana de reversión acordada con el responsable de la aplicación.',
  },
  H02: {
    titulo: 'Habilitar MFA administrativo y eliminar cuentas compartidas',
    activo: 'DB-LAB (10.60.20.20)',
    evidencia: 'La configuración del servidor reporta mfa_administracion = false y cuentas_compartidas = true. Con cuentas compartidas, un acceso no se puede atribuir a una persona.',
    cambio: 'Crear credenciales individuales para cada administrador, exigir segundo factor en el acceso administrativo y deshabilitar las cuentas compartidas tras un período de transición.',
    responsable: 'Administrador de base de datos / responsable de identidades',
    beneficio: 'Un acceso pasa a ser atribuible a una persona, y una contraseña filtrada deja de ser suficiente para entrar.',
    riesgo: 'Procesos automáticos que hoy usen la cuenta compartida dejarían de funcionar. Hay que inventariarlos antes y migrarlos a cuentas de servicio.',
    validacion: 'Verificar que cada administrador entra con su cuenta y segundo factor, y que la cuenta compartida queda deshabilitada sin afectar los procesos migrados.',
    reversion: 'Mantener una cuenta de contingencia con credencial custodiada en bóveda, de uso registrado y auditado, hasta cerrar la transición.',
  },
  H03: {
    titulo: 'Activar el envío de registros hacia LOG-LAB',
    activo: 'DB-LAB (10.60.20.20) → LOG-LAB (10.60.0.30)',
    evidencia: 'La configuración reporta registro_centralizado = false. Combinado con R02, que tampoco registra, el activo más crítico del escenario no deja rastro consultable.',
    cambio: 'Configurar el reenvío de eventos del servidor hacia LOG-LAB mediante syslog sobre TLS, y sincronizar el reloj con la misma fuente de tiempo que el resto de activos.',
    responsable: 'Administrador de servidores / seguridad',
    beneficio: 'Permite reconstruir qué pasó y cuándo. Sin esto, cualquier investigación posterior depende de registros locales que pueden alterarse.',
    riesgo: 'Aumenta el volumen almacenado en LOG-LAB y el tráfico de gestión. Hay que dimensionar retención antes de activarlo.',
    validacion: 'Confirmar que un intento de acceso fallido generado a propósito aparece en LOG-LAB con la hora correcta y en menos de un minuto.',
    reversion: 'Desactivar el reenvío en la configuración del servidor. El cambio no afecta el servicio de base de datos.',
  },
};

function prioridad(p) {
  if (p >= 6) return { etiqueta: 'Alta', clase: 'sev-critica' };
  if (p >= 3) return { etiqueta: 'Media', clase: 'sev-media' };
  return { etiqueta: 'Baja', clase: 'sev-baja' };
}

export function render(st) {
  estado = st;
  return `
  <section class="panel">
    <div class="panel-cab">
      <div>
        <h2>Matriz de priorización</h2>
        <p class="panel-sub">Puntaje = impacto (1–3) × exposición (1–3). De 6 a 9 alta, de 3 a 4 media, de 1 a 2 baja. <strong>No es CVSS</strong> ni una metodología oficial de la empresa.</p>
      </div>
      <button id="btn-exportar" class="btn btn-fantasma">Exportar plan en CSV</button>
    </div>
    <div class="tabla-env">
      <table class="tabla">
        <thead><tr>
          <th>ID</th><th>Activo</th><th>Categoría</th><th>Evidencia</th>
          <th class="num">Impacto</th><th class="num">Exposición</th><th class="num">Puntaje</th><th>Prioridad</th>
        </tr></thead>
        <tbody id="tbody-matriz"></tbody>
      </table>
    </div>
    <p class="nota">Mueve los deslizadores para argumentar la valoración en vivo. El orden y las prioridades se recalculan al instante.</p>
  </section>

  <section class="panel">
    <div class="panel-cab"><h2>Fichas de hardening priorizadas</h2></div>
    <p class="panel-sub">Las tres primeras por puntaje. Cada una registra evidencia, cambio, responsable por rol, efecto en la operación, validación y reversión. Se proponen; no se aplican desde aquí.</p>
    <div id="fichas" class="fichas"></div>
  </section>`;
}

function pintarMatriz() {
  const ordenados = estado.hallazgos.slice()
    .sort((a, b) => (b.impacto * b.exposicion) - (a.impacto * a.exposicion));

  el('tbody-matriz').innerHTML = ordenados.map(h => {
    const p = h.impacto * h.exposicion;
    const pr = prioridad(p);
    return `<tr>
      <td class="mono">${esc(h.hallazgo_id)}</td>
      <td><strong>${esc(h.activo)}</strong></td>
      <td>${esc(h.categoria)}</td>
      <td class="celda-evidencia">${esc(h.evidencia)}
        ${h.precisar ? '<div class="aviso-inline">Sin versiones ni boletines: no permite inferir una vulnerabilidad concreta. Hay que pedir el detalle a la empresa.</div>' : ''}
      </td>
      <td class="num"><input type="range" min="1" max="3" value="${h.impacto}" data-h="${esc(h.hallazgo_id)}" data-campo="impacto"><span class="valor">${h.impacto}</span></td>
      <td class="num"><input type="range" min="1" max="3" value="${h.exposicion}" data-h="${esc(h.hallazgo_id)}" data-campo="exposicion"><span class="valor">${h.exposicion}</span></td>
      <td class="num"><strong class="puntaje">${p}</strong></td>
      <td><span class="pill ${pr.clase}">${pr.etiqueta}</span></td>
    </tr>`;
  }).join('');

  el('tbody-matriz').querySelectorAll('input[type=range]').forEach(r => {
    r.addEventListener('input', () => {
      const h = estado.hallazgos.find(x => x.hallazgo_id === r.getAttribute('data-h'));
      h[r.getAttribute('data-campo')] = parseInt(r.value, 10);
      pintarMatriz(); pintarFichas();
    });
  });
}

function pintarFichas() {
  const top = estado.hallazgos.slice()
    .sort((a, b) => (b.impacto * b.exposicion) - (a.impacto * a.exposicion))
    .slice(0, 3);

  el('fichas').innerHTML = top.map((h, i) => {
    const f = FICHAS[h.hallazgo_id];
    const p = h.impacto * h.exposicion;
    const pr = prioridad(p);
    if (!f) {
      return `<article class="ficha">
        <div class="ficha-cab"><span class="orden">${i + 1}</span>
          <div><h3>${esc(h.hallazgo_id)} · ${esc(h.categoria)}</h3>
          <span class="sutil">${esc(h.activo)}</span></div>
          <span class="pill ${pr.clase}">${pr.etiqueta} · ${p}</span></div>
        <p class="ficha-pendiente">Ficha técnica pendiente de redactar para este hallazgo.</p>
      </article>`;
    }
    return `<article class="ficha">
      <div class="ficha-cab">
        <span class="orden">${i + 1}</span>
        <div><h3>${esc(h.hallazgo_id)} · ${esc(f.titulo)}</h3><span class="sutil">${esc(f.activo)}</span></div>
        <span class="pill ${pr.clase}">${pr.etiqueta} · ${p}</span>
      </div>
      <dl class="ficha-datos">
        <dt>Evidencia</dt><dd>${esc(f.evidencia)}</dd>
        <dt>Cambio propuesto</dt><dd>${esc(f.cambio)}</dd>
        <dt>Responsable (rol)</dt><dd>${esc(f.responsable)}</dd>
        <dt>Beneficio esperado</dt><dd>${esc(f.beneficio)}</dd>
        <dt>Efecto en la operación</dt><dd>${esc(f.riesgo)}</dd>
        <dt>Validación</dt><dd>${esc(f.validacion)}</dd>
        <dt>Reversión</dt><dd>${esc(f.reversion)}</dd>
      </dl>
    </article>`;
  }).join('');
}

function exportarCSV() {
  const cab = ['hallazgo', 'activo', 'evidencia', 'impacto_1a3', 'exposicion_1a3', 'puntaje',
    'prioridad', 'cambio_propuesto', 'responsable_rol', 'riesgo_operativo', 'validacion', 'reversion', 'estado'];
  const q = v => '"' + String(v == null ? '' : v).replace(/"/g, '""') + '"';

  const filas = estado.hallazgos.slice()
    .sort((a, b) => (b.impacto * b.exposicion) - (a.impacto * a.exposicion))
    .map(h => {
      const p = h.impacto * h.exposicion;
      const f = FICHAS[h.hallazgo_id] || {};
      return [h.hallazgo_id, h.activo, h.evidencia, h.impacto, h.exposicion, p,
        prioridad(p).etiqueta, f.cambio || '', f.responsable || '', f.riesgo || '',
        f.validacion || '', f.reversion || '', 'Propuesto'].map(q).join(',');
    });

  descargar('plan_hardening.csv', '﻿' + cab.join(',') + '\n' + filas.join('\n'), 'text/csv');
}

export function montar(st) {
  estado = st;
  el('btn-exportar').addEventListener('click', exportarCSV);
  pintarMatriz(); pintarFichas();
}
