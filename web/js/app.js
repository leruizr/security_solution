/* Arranque y navegacion entre vistas. */
import { el } from './ui.js';
import { analizar } from './motor.js';
import * as metricas from './vistas/metricas.js';
import * as dashboard from './vistas/dashboard.js';
import * as correlacion from './vistas/correlacion.js';
import * as hardening from './vistas/hardening.js';
import { SEMILLA } from './vistas/hardening.js';
import * as validacion from './vistas/validacion.js';
import * as entregables from './vistas/entregables.js';

const VISTAS = [
  { id: 'metricas', nombre: 'Panorama', mod: metricas, icono: 'M3 3v18h18M7 16l3-6 4 3 3-7' },
  { id: 'dashboard', nombre: 'Monitor', mod: dashboard, icono: 'M3 3v18h18M7 16l4-6 4 3 5-8' },
  { id: 'correlacion', nombre: 'Correlación', mod: correlacion, icono: 'M9 3H5a2 2 0 0 0-2 2v4m6-6h10a2 2 0 0 1 2 2v4M9 21H5a2 2 0 0 1-2-2v-4m6 6h10a2 2 0 0 0 2-2v-4M8 12h8' },
  { id: 'hardening', nombre: 'Hardening', mod: hardening, icono: 'M20 13c0 5-3.5 7.5-7.66 8.95a1 1 0 0 1-.67-.01C7.5 20.5 4 18 4 13V6a1 1 0 0 1 1-1c2 0 4.5-1.2 6.24-2.72a1.17 1.17 0 0 1 1.52 0C14.51 3.81 17 5 19 5a1 1 0 0 1 1 1z' },
  { id: 'validacion', nombre: 'Validación', mod: validacion, icono: 'M9 11l3 3L22 4M21 12v7a2 2 0 0 1-2 2H5a2 2 0 0 1-2-2V5a2 2 0 0 1 2-2h11' },
  { id: 'entregables', nombre: 'Entregables', mod: entregables, icono: 'M14 2H6a2 2 0 0 0-2 2v16a2 2 0 0 0 2 2h12a2 2 0 0 0 2-2V8zM14 2v6h6M16 13H8M16 17H8' },
];

let estado = null;
let vistaActual = 'metricas';

function pintarNav() {
  el('nav-vistas').innerHTML = VISTAS.map(v => `
    <button class="tab ${v.id === vistaActual ? 'activa' : ''}" data-vista="${v.id}" role="tab">
      <svg class="ico" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><path d="${v.icono}"/></svg>
      <span>${v.nombre}</span>
    </button>`).join('');

  el('nav-vistas').querySelectorAll('[data-vista]').forEach(b =>
    b.addEventListener('click', () => ir(b.getAttribute('data-vista'))));
}

function ir(id) {
  vistaActual = id;
  const v = VISTAS.find(x => x.id === id);
  const app = el('app');
  app.innerHTML = v.mod.render(estado);
  v.mod.montar(estado, recalcular);
  pintarNav();
  window.scrollTo({ top: 0, behavior: 'instant' });
}

/* Cambia el conjunto de eventos y vuelve a correr el motor completo.
 * Con null vuelve al conjunto oficial del curso. */
function recalcular(nuevo) {
  if (nuevo) {
    estado.eventos = nuevo.eventos;
    estado.nombre_dataset = nuevo.nombre;
  } else {
    estado.eventos = estado.eventos_oficiales;
    estado.nombre_dataset = 'Laboratorio Kenworth';
  }
  estado.alertas = analizar(estado.eventos, estado);
  ir(vistaActual);
}

function modoPitch() {
  const activo = document.body.classList.toggle('pitch');
  el('btn-pitch').classList.toggle('activo', activo);
}

function fallo(mensaje, detalle) {
  el('cargando').innerHTML = `
    <div class="error-carga">
      <h2>${mensaje}</h2>
      <p>${detalle}</p>
    </div>`;
}

fetch('alertas.json', { cache: 'no-store' })
  .then(r => { if (!r.ok) throw new Error('HTTP ' + r.status); return r.json(); })
  .then(d => {
    estado = {
      generado_en: d.generado_en,
      parametros: d.parametros,
      inventario: d.inventario || [],
      /* La puntuacion impacto/exposicion es valoracion del equipo, no viene del
         paquete del curso. Se siembra aqui para que el KPI del monitor y la
         matriz de hardening lean siempre los mismos numeros. */
      hallazgos: (d.hallazgos || []).map(h => {
        const s = SEMILLA[h.hallazgo_id] || { impacto: 2, exposicion: 2 };
        return { ...h, impacto: s.impacto, exposicion: s.exposicion, precisar: !!s.precisar };
      }),
      cambios_autorizados: d.cambios_autorizados || [],
      politicas: d.politicas || [],
      servidores: d.servidores || {},
      casos_controlados: d.casos_controlados || [],
      eventos_oficiales: d.eventos || [],
      eventos: d.eventos || [],
      alertas_python: d.alertas || [],
      nombre_dataset: 'Laboratorio Kenworth',
    };
    estado.alertas = analizar(estado.eventos, estado);

    el('pie-generado').textContent = String(d.generado_en || '').replace('T', ' a las ');
    el('cargando').classList.add('oculto');
    el('app').classList.remove('oculto');

    el('btn-pitch').addEventListener('click', modoPitch);
    el('modal-cerrar').addEventListener('click', () => el('modal').close());

    ir('metricas');
  })
  .catch(err => {
    if (location.protocol === 'file:') {
      fallo('Abre el tablero con un servidor local',
        'El navegador bloquea la lectura de archivos con <code>file://</code>. Ejecuta <code>cd web && python3 -m http.server 8000</code> y abre <code>http://localhost:8000</code>. En Vercel funciona directamente.');
    } else {
      fallo('No se pudo cargar alertas.json',
        'Ejecuta <code>python3 analizador/analizador.py</code> para generarlo. (' + err.message + ')');
    }
  });
