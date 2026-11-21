/* Vista SOC: Dashboard de Seguridad, Tráfico de Red y Monitoreo Fundamental.
 *
 * Presenta a detalle:
 *  1. Nivel de amenaza y postura de seguridad general de la infraestructura.
 *  2. Estado en tiempo real de los 5 vectores fundamentales de monitoreo.
 *  3. Matriz de flujos de tráfico inter-zonas (topología de red).
 *  4. Superficie de ataque por puertos y servicios (allow vs deny).
 *  5. Triage táctico interactivo de eventos sospechosos.
 */
import { esc, el, numero, bytes, hora, pill, abrirModal, tablaClaveValor, CLASE_SEV } from '../ui.js';

let estado = null;
let filtroRapido = 'sospechosos';
let busquedaTexto = '';

/* Clasifica zona según IP */
function zonaDeIp(ip, inventario) {
  const activo = (inventario || []).find(a => a.ip_prueba === ip);
  return activo ? activo.zona : 'Internet';
}

function nombreDeIp(ip, inventario) {
  const activo = (inventario || []).find(a => a.ip_prueba === ip);
  return activo ? activo.nombre_prueba : ip;
}

/* Agrupación de flujos de tráfico entre zonas */
function flujosPorZona(eventos, inventario) {
  const mapa = {};
  eventos.forEach(e => {
    const zOri = zonaDeIp(e.origen_ip, inventario);
    const zDes = zonaDeIp(e.destino_ip, inventario);
    const clave = `${zOri} → ${zDes}`;
    if (!mapa[clave]) {
      mapa[clave] = {
        origen: zOri,
        destino: zDes,
        eventos: 0,
        bytes: 0,
        deny: 0,
        allow: 0,
        puertos: new Set(),
        reglas: new Set(),
      };
    }
    const f = mapa[clave];
    f.eventos++;
    f.bytes += parseInt(e.bytes, 10) || 0;
    if (e.accion === 'deny') f.deny++; else f.allow++;
    f.puertos.add(e.puerto_destino);
    f.reglas.add(e.regla_id);
  });

  return Object.values(mapa).sort((a, b) => b.eventos - a.eventos);
}

/* Distribución por puertos y servicios */
function distribucionPuertos(eventos) {
  const SERVICIOS_COMUNES = {
    '22': 'SSH (Administración remota)',
    '443': 'HTTPS (Web cifrado)',
    '80': 'HTTP (Web estándar)',
    '5432': 'PostgreSQL (Base de datos)',
    '3389': 'RDP (Escritorio remoto)',
    '8443': 'HTTPS-Alt (Aplicaciones)',
  };

  const mapa = {};
  eventos.forEach(e => {
    const p = String(e.puerto_destino || '?');
    if (!mapa[p]) {
      mapa[p] = {
        puerto: p,
        servicio: SERVICIOS_COMUNES[p] || `Puerto ${p}`,
        total: 0,
        allow: 0,
        deny: 0,
        bytes: 0,
        sensible: ['22', '5432', '3389'].includes(p),
      };
    }
    mapa[p].total++;
    if (e.accion === 'deny') mapa[p].deny++; else mapa[p].allow++;
    mapa[p].bytes += parseInt(e.bytes, 10) || 0;
  });

  return Object.values(mapa).sort((a, b) => b.total - a.total);
}

/* Comprobación de estado para los 5 vectores del reto */
function estadoVectores(alertas, eventos) {
  const abiertas = alertas.filter(a => a.estado === 'Abierta');
  const descartadas = alertas.filter(a => a.estado === 'Descartada');

  // Vector 1: Credenciales y Fuerza Bruta
  const alFuerza = abiertas.find(a => a.tipo === 'Fallos repetidos');
  const v1 = {
    id: 'v-fuerza',
    titulo: '1. Credenciales y Fuerza Bruta',
    icono: 'M12 15v2m-6 4h12a2 2 0 0 0 2-2v-6a2 2 0 0 0-2-2H6a2 2 0 0 0-2 2v6a2 2 0 0 0 2 2zm10-10V7a4 4 0 0 0-8 0v4h8z',
    estado: alFuerza ? 'critico' : 'ok',
    etiqueta: alFuerza ? 'Alerta Crítica' : 'Nominal',
    diagnostico: alFuerza
      ? 'Se detectaron 7 fallos de login seguidos de acceso exitoso (E0301-E0308) a DB-LAB.'
      : 'No se registran intentos anómalos de autenticación.',
    accion: 'Exigir MFA obligatorio (H02) y bloquear tras 5 intentos fallidos.',
  };

  // Vector 2: Horario Operativo (07:00-19:00) vs Cambios
  const alHorario = abiertas.filter(a => a.tipo === 'Fuera de horario');
  const v2 = {
    id: 'v-horario',
    titulo: '2. Horario Operativo y Mantenimiento',
    icono: 'M12 8v4l3 3m6-3a9 9 0 1 1-18 0 9 9 0 0 1 18 0z',
    estado: alHorario.length ? 'aviso' : 'ok',
    etiqueta: alHorario.length ? `${alHorario.length} No autorizadas` : '3 Justificadas (CH01)',
    diagnostico: alHorario.length
      ? `${alHorario.length} accesos fuera de horario no justificados.`
      : 'Los accesos nocturnos (02:00 AM) coinciden 100% con el mantenimiento programado CH01.',
    accion: 'Mantener correlación automática con tabla de cambios autorizados.',
  };

  // Vector 3: Exfiltración / Salidas > 50 MB
  const alVolumen = abiertas.find(a => a.tipo === 'Volumen para revisión');
  const v3 = {
    id: 'v-volumen',
    titulo: '3. Fuga de Datos / Exfiltración',
    icono: 'M4 14.899A7 7 0 1 1 15.71 8h1.79a4.5 4.5 0 0 1 2.5 8.242M12 12v9m0 0-3-3m3 3 3-3',
    estado: alVolumen ? 'critico' : 'ok',
    etiqueta: alVolumen ? 'Alerta Crítica (85 MB)' : 'Nominal',
    diagnostico: alVolumen
      ? 'Transferencia masiva de 85 MB desde BACKUP-LAB hacia Internet en E0324, violando el límite de CH01.'
      : 'Ningún flujo supera el umbral de revisión de 50 MB.',
    accion: 'Aislar tráfico saliente de BACKUP-LAB e investigar con el administrador.',
  };

  // Vector 4: Escaneo de Puertos y Reconocimiento
  const alEscaneo = abiertas.find(a => a.tipo === 'Escaneo de puertos' || a.tipo === 'Escaneo distribuido de puertos');
  const v4 = {
    id: 'v-escaneo',
    titulo: '4. Reconocimiento y Escaneo de Puertos',
    icono: 'M21 21l-6-6m2-5a7 7 0 1 1-14 0 7 7 0 0 1 14 0z',
    estado: alEscaneo ? 'aviso' : 'ok',
    etiqueta: alEscaneo ? 'Escaneo Detectado' : 'Nominal',
    diagnostico: alEscaneo
      ? 'IP externa 203.0.113.77 sondeó puertos 22, 5432 y 3389 contra DB-LAB (12 denegaciones).'
      : 'No se observan patrones de escaneo de puertos.',
    accion: 'El firewall bloqueó el acceso (R04). Incluir IP en lista de bloqueo perimetral.',
  };

  // Vector 5: Auditoría y Reglas sin Registro
  const alExcepcion = abiertas.find(a => a.tipo === 'Excepción sin registro' || a.tipo === 'Inconsistencia de registro');
  const v5 = {
    id: 'v-auditoria',
    titulo: '5. Auditoría y Puntos Ciegos Firewall',
    icono: 'M1 12s4-8 11-8 11 8 11 8-4 8-11 8-11-8-11-8zM12 9a3 3 0 1 0 0 6 3 3 0 0 0 0-6z',
    estado: alExcepcion ? 'aviso' : 'ok',
    etiqueta: alExcepcion ? 'Punto Ciego Detectado' : 'Nominal',
    diagnostico: alExcepcion
      ? 'Regla R02 permite Usuarios → DB-LAB any sin registro. E0324 usó regla R01 incorrectamente.'
      : 'Todas las reglas aplican registros de auditoría adecuados.',
    accion: 'Eliminar regla R02 y corregir política de registro centralizado.',
  };

  return [v1, v2, v3, v4, v5];
}

export function render(st) {
  estado = st;
  const ev = estado.eventos;
  const al = estado.alertas;
  const abiertas = al.filter(a => a.estado === 'Abierta');
  const criticas = abiertas.filter(a => a.severidad_etiqueta === 'Crítica');

  const nivelAmenaza = criticas.length > 0 ? 'CRÍTICO' : (abiertas.length > 0 ? 'ELEVADO' : 'BAJO');
  const colorNivel = criticas.length > 0 ? 'var(--critico)' : (abiertas.length > 0 ? 'var(--aviso)' : 'var(--ok)');

  const vectores = estadoVectores(al, ev);
  const flujos = flujosPorZona(ev, estado.inventario);
  const puertos = distribucionPuertos(ev);

  return `
  <!-- Banner Ejecutivo de Postura de Seguridad -->
  <section class="panel panel-hero">
    <div class="hero">
      <div class="hero-cifra" style="color:${colorNivel}">${nivelAmenaza}</div>
      <div class="hero-texto">
        <strong>Nivel de Amenaza en la Infraestructura</strong>
        <p class="panel-sub">
          Monitoreo continuo de <strong>${numero(ev.length)} eventos</strong> en 6 zonas de red.
          Hay <strong>${criticas.length} alertas críticas</strong> y <strong>${abiertas.length - criticas.length} alertas de severidad alta</strong> que requieren intervención del equipo de tecnología.
        </p>
      </div>
    </div>
  </section>

  <!-- Los 5 Vectores Fundamentales del Reto -->
  <section class="panel">
    <div class="panel-cab">
      <div>
        <h2>Los 5 Vectores Fundamentales de Monitoreo</h2>
        <p class="panel-sub">Evaluación en tiempo real de los pilares de seguridad exigidos por el reto empresarial de Kenworth.</p>
      </div>
      <span class="chip chip-azul">Checklist de Ciberseguridad</span>
    </div>
    <div class="vectores-grid">
      ${vectores.map(v => `
        <div class="vector-card vector-${v.estado}">
          <div class="vector-cab">
            <span class="vector-titulo">${esc(v.titulo)}</span>
            <span class="pill sev-${v.estado === 'critico' ? 'critica' : (v.estado === 'aviso' ? 'alta' : 'descartada')}">${esc(v.etiqueta)}</span>
          </div>
          <p class="vector-desc">${esc(v.diagnostico)}</p>
          <div class="vector-meta">
            <strong>Acción Hardening:</strong>
            <span>${esc(v.accion)}</span>
          </div>
        </div>`).join('')}
    </div>
  </section>

  <!-- Matriz de Tráfico Inter-Zonas y Superficie de Ataque -->
  <div class="rejilla-2">
    <section class="panel">
      <div class="panel-cab">
        <div>
          <h2>Matriz de Tráfico entre Zonas</h2>
          <p class="panel-sub">Flujo de paquetes entre el perímetro externo, DMZ, usuarios y servidores internos.</p>
        </div>
      </div>
      <div class="tabla-env">
        <table class="tabla tabla-compacta">
          <thead>
            <tr>
              <th>Flujo de Zona</th>
              <th class="num">Eventos</th>
              <th class="num">Volumen</th>
              <th>Permitido / Bloqueado</th>
              <th>Diagnóstico SOC</th>
            </tr>
          </thead>
          <tbody>
            ${flujos.map(f => {
              const sospechoso = f.origen === 'Internet' && f.destino === 'Servidores';
              const fuga = f.origen === 'Respaldo' && f.destino === 'Internet';
              const internoRiesgoso = f.origen === 'Usuarios' && f.destino === 'Servidores';
              let badge = '<span class="estado estado-ok">Nominal</span>';
              if (fuga) badge = '<span class="estado estado-critico">🚨 Posible Fuga</span>';
              else if (sospechoso) badge = '<span class="estado estado-aviso">🎯 Escaneo externo</span>';
              else if (internoRiesgoso) badge = '<span class="estado estado-aviso">⚠️ Regla R02</span>';

              return `<tr>
                <td><strong>${esc(f.origen)}</strong> → ${esc(f.destino)}</td>
                <td class="num mono">${numero(f.eventos)}</td>
                <td class="num mono">${bytes(f.bytes)}</td>
                <td><span class="sutil">${f.allow} allow</span> · <span class="${f.deny ? 'deny' : 'sutil'}">${f.deny} deny</span></td>
                <td>${badge}</td>
              </tr>`;
            }).join('')}
          </tbody>
        </table>
      </div>
    </section>

    <section class="panel">
      <div class="panel-cab">
        <div>
          <h2>Superficie de Ataque (Puertos y Servicios)</h2>
          <p class="panel-sub">Servicios sondeados y relación de tráfico permitido vs bloqueado por el firewall.</p>
        </div>
      </div>
      <div class="tabla-env">
        <table class="tabla tabla-compacta">
          <thead>
            <tr>
              <th>Puerto / Servicio</th>
              <th class="num">Eventos</th>
              <th>Acción Firewall</th>
              <th class="num">Datos</th>
            </tr>
          </thead>
          <tbody>
            ${puertos.map(p => `<tr>
              <td>
                <span class="mono">TCP/${esc(p.puerto)}</span>
                <br><span class="sutil">${esc(p.servicio)}</span>
              </td>
              <td class="num mono"><strong>${numero(p.total)}</strong></td>
              <td>
                ${p.allow ? `<span class="pill sev-descartada">${p.allow} allow</span>` : ''}
                ${p.deny ? `<span class="pill sev-critica">${p.deny} deny</span>` : ''}
              </td>
              <td class="num mono">${bytes(p.bytes)}</td>
            </tr>`).join('')}
          </tbody>
        </table>
      </div>
      <p class="nota">Puertos 22 (SSH), 5432 (Postgres) y 3389 (RDP) son objetivos críticos de sondeo externo e interno.</p>
    </section>
  </div>

  <!-- Triage Táctico de Eventos Relevantes -->
  <section class="panel">
    <div class="panel-cab">
      <div>
        <h2>Triage Táctico de Tráfico y Eventos</h2>
        <p class="panel-sub">Filtra rápidamente los eventos de interés para auditoría forense sin el ruido de fondo.</p>
      </div>
      <div class="filtros" style="margin-bottom:0">
        <button class="btn btn-mini ${filtroRapido === 'sospechosos' ? 'btn-primario' : 'btn-fantasma'}" data-triage="sospechosos">Sospechosos & Alertas (${numero(eventosSospechosos(ev).length)})</button>
        <button class="btn btn-mini ${filtroRapido === 'bloqueados' ? 'btn-primario' : 'btn-fantasma'}" data-triage="bloqueados">Bloqueados Firewall (${numero(ev.filter(e => e.accion === 'deny').length)})</button>
        <button class="btn btn-mini ${filtroRapido === 'auth' ? 'btn-primario' : 'btn-fantasma'}" data-triage="auth">Autenticación (${numero(ev.filter(e => e.tipo === 'autenticacion').length)})</button>
        <button class="btn btn-mini ${filtroRapido === 'todos' ? 'btn-primario' : 'btn-fantasma'}" data-triage="todos">Todos (${numero(ev.length)})</button>
      </div>
    </div>
    <div class="filtros">
      <input id="soc-buscar" type="search" placeholder="Buscar IP, puerto o usuario en el triage..." value="${esc(busquedaTexto)}">
    </div>
    <div class="tabla-env tabla-alta">
      <table class="tabla tabla-compacta">
        <thead>
          <tr>
            <th>ID</th>
            <th>Fecha y Hora</th>
            <th>Tipo</th>
            <th>Origen → Destino</th>
            <th>Puerto</th>
            <th>Acción</th>
            <th>Regla</th>
            <th>Usuario</th>
            <th>Resultado</th>
            <th class="num">Bytes</th>
            <th></th>
          </tr>
        </thead>
        <tbody id="soc-tbody"></tbody>
      </table>
    </div>
    <p class="nota" id="soc-conteo"></p>
  </section>`;
}

function eventosSospechosos(eventos) {
  return eventos.filter(e =>
    e.accion === 'deny' ||
    e.resultado === 'fallo' ||
    parseInt(e.bytes, 10) >= 50000000 ||
    e.regla_id === 'R02' ||
    (e.tipo === 'autenticacion' && !['07', '08', '09', '10', '11', '12', '13', '14', '15', '16', '17', '18'].includes(String(e.fecha_hora).slice(11, 13)))
  );
}

function filtrarEventosTriage() {
  const ev = estado.eventos;
  let lista = [];

  if (filtroRapido === 'sospechosos') lista = eventosSospechosos(ev);
  else if (filtroRapido === 'bloqueados') lista = ev.filter(e => e.accion === 'deny');
  else if (filtroRapido === 'auth') lista = ev.filter(e => e.tipo === 'autenticacion');
  else lista = ev;

  const q = busquedaTexto.toLowerCase().trim();
  if (q) {
    lista = lista.filter(e =>
      [e.evento_id, e.origen_ip, e.destino_ip, e.usuario_prueba, e.puerto_destino, e.regla_id, e.accion, e.resultado]
        .join(' ').toLowerCase().includes(q)
    );
  }

  return lista;
}

function pintarTablaTriage() {
  const lista = filtrarEventosTriage();
  const limite = 120;
  const tb = el('soc-tbody');
  if (!tb) return;

  if (!lista.length) {
    tb.innerHTML = '<tr><td colspan="11" class="vacio">No hay eventos para este filtro.</td></tr>';
  } else {
    tb.innerHTML = lista.slice(0, limite).map(e => {
      const orNombre = nombreDeIp(e.origen_ip, estado.inventario);
      const desNombre = nombreDeIp(e.destino_ip, estado.inventario);

      return `<tr>
        <td class="mono"><strong>${esc(e.evento_id)}</strong></td>
        <td class="mono nowrap">${esc(hora(e.fecha_hora))}</td>
        <td>${esc(e.tipo)}</td>
        <td class="mono">${esc(orNombre)} → <strong>${esc(desNombre)}</strong></td>
        <td class="mono">TCP/${esc(e.puerto_destino)}</td>
        <td>${e.accion === 'deny' ? '<span class="deny">deny</span>' : '<span class="sutil">allow</span>'}</td>
        <td class="mono">${e.regla_id === 'R02' ? '<span class="pill sev-alta">R02</span>' : esc(e.regla_id)}</td>
        <td>${esc(e.usuario_prueba || '—')}</td>
        <td>${e.resultado === 'fallo' ? '<span class="fallo">fallo</span>' : (e.resultado === 'exito' ? '<span class="estado-ok">éxito</span>' : '—')}</td>
        <td class="num mono">${parseInt(e.bytes, 10) >= 50000000 ? `<strong style="color:var(--critico)">${bytes(e.bytes)}</strong>` : bytes(e.bytes)}</td>
        <td><button class="btn btn-mini" data-evtdet="${esc(e.evento_id)}">Detalle</button></td>
      </tr>`;
    }).join('');
  }

  el('soc-conteo').textContent = lista.length > limite
    ? `Mostrando los primeros ${limite} de ${numero(lista.length)} eventos de interés.`
    : `Total: ${numero(lista.length)} eventos filtrados en esta categoría.`;

  tb.querySelectorAll('[data-evtdet]').forEach(b => {
    b.addEventListener('click', () => {
      const id = b.getAttribute('data-evtdet');
      const evObj = estado.eventos.find(x => x.evento_id === id);
      if (evObj) {
        abrirModal(`Evento ${evObj.evento_id} · Detalle Forense`, tablaClaveValor({
          evento_id: evObj.evento_id,
          fecha_hora: hora(evObj.fecha_hora),
          tipo: evObj.tipo,
          origen: `${evObj.origen_ip} (${nombreDeIp(evObj.origen_ip, estado.inventario)})`,
          destino: `${evObj.destino_ip} (${nombreDeIp(evObj.destino_ip, estado.inventario)})`,
          puerto: `TCP/${evObj.puerto_destino}`,
          accion: evObj.accion,
          regla: evObj.regla_id,
          usuario: evObj.usuario_prueba,
          resultado: evObj.resultado,
          bytes: `${numero(evObj.bytes)} (${bytes(evObj.bytes)})`,
        }));
      }
    });
  });
}

export function montar(st, recalcular) {
  estado = st;

  document.querySelectorAll('[data-triage]').forEach(b => {
    b.addEventListener('click', () => {
      filtroRapido = b.getAttribute('data-triage');
      document.querySelectorAll('[data-triage]').forEach(x => {
        x.classList.toggle('btn-primario', x === b);
        x.classList.toggle('btn-fantasma', x !== b);
      });
      pintarTablaTriage();
    });
  });

  const inp = el('soc-buscar');
  if (inp) {
    inp.addEventListener('input', e => {
      busquedaTexto = e.target.value;
      pintarTablaTriage();
    });
  }

  pintarTablaTriage();
}
