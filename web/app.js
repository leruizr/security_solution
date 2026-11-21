/* Tablero de alertas - v0
 *
 * Lee web/alertas.json, que genera analizador/analizador.py.
 * No tiene dependencias ni llamadas a servicios externos.
 *
 * PENDIENTE (siguiente fase): columna de severidad con semaforo, cierre por CH01,
 * enriquecimiento con el inventario (activo, zona, criticidad) y registro de
 * disposicion por alerta.
 */
'use strict';

var CLASES_TIPO = {
  'Fallos repetidos': 't-fallos',
  'Volumen para revisión': 't-volumen',
  'Fuera de horario': 't-horario',
  'Inconsistencia de registro': 't-inconsistencia'
};

var datos = null;
var porId = {};

function el(id) { return document.getElementById(id); }

function txt(valor) {
  var d = document.createElement('div');
  d.textContent = valor == null ? '' : String(valor);
  return d.innerHTML;
}

function mostrarAviso(html) {
  var caja = el('estado');
  caja.innerHTML = html;
  caja.classList.remove('oculto');
}

function pintarTarjetas(resumen) {
  var items = [
    { cifra: resumen.eventos, etiqueta: 'Eventos analizados' },
    { cifra: resumen.alertas, etiqueta: 'Alertas generadas' }
  ];
  Object.keys(resumen.por_tipo || {}).forEach(function (tipo) {
    items.push({ cifra: resumen.por_tipo[tipo], etiqueta: tipo });
  });
  el('tarjetas').innerHTML = items.map(function (i) {
    return '<div class="tarjeta"><div class="cifra">' + txt(i.cifra) +
           '</div><div class="etiqueta">' + txt(i.etiqueta) + '</div></div>';
  }).join('');
}

function pintarFiltroTipos(alertas) {
  var tipos = [];
  alertas.forEach(function (a) {
    if (tipos.indexOf(a.tipo) === -1) tipos.push(a.tipo);
  });
  var sel = el('f-tipo');
  tipos.sort().forEach(function (t) {
    var o = document.createElement('option');
    o.value = t; o.textContent = t;
    sel.appendChild(o);
  });
}

function filtrar() {
  var tipo = el('f-tipo').value;
  var q = el('f-texto').value.trim().toLowerCase();
  return datos.alertas.filter(function (a) {
    if (tipo && a.tipo !== tipo) return false;
    if (!q) return true;
    return (a.alerta_id + ' ' + a.evento_id + ' ' + a.tipo + ' ' + a.motivo)
      .toLowerCase().indexOf(q) !== -1;
  });
}

function pintarTabla() {
  var filas = filtrar();
  var cuerpo = document.querySelector('#tabla tbody');

  if (!filas.length) {
    cuerpo.innerHTML = '<tr><td colspan="5" class="nota">Sin alertas para este filtro.</td></tr>';
  } else {
    cuerpo.innerHTML = filas.map(function (a) {
      var clase = CLASES_TIPO[a.tipo] || '';
      return '<tr>' +
        '<td class="id">' + txt(a.alerta_id) + '</td>' +
        '<td class="hora">' + txt(a.fecha_hora.replace('T', ' ')) + '</td>' +
        '<td><span class="pill ' + clase + '">' + txt(a.tipo) + '</span></td>' +
        '<td>' + txt(a.motivo) + '</td>' +
        '<td><button class="ver" data-alerta="' + txt(a.alerta_id) + '">' +
          txt(a.evento_id) + ' →</button></td>' +
      '</tr>';
    }).join('');
  }

  el('nota-conteo').textContent =
    'Mostrando ' + filas.length + ' de ' + datos.alertas.length +
    ' alertas. Una alerta es una señal para revisión: no equivale a un incidente confirmado.';

  Array.prototype.forEach.call(cuerpo.querySelectorAll('button.ver'), function (b) {
    b.addEventListener('click', function () { abrirEvidencia(b.getAttribute('data-alerta')); });
  });
}

/* Evidencia: de la alerta al evento crudo que la origino, en un clic.
   Es el recorrido que la guia pide poder demostrar. */
function abrirEvidencia(alertaId) {
  var alerta = null;
  datos.alertas.forEach(function (a) { if (a.alerta_id === alertaId) alerta = a; });
  if (!alerta) return;

  var evento = porId[alerta.evento_id];
  el('detalle-titulo').textContent = alerta.alerta_id + ' · ' + alerta.tipo;

  var html = '<p class="motivo">' + txt(alerta.motivo) + '</p>';
  if (evento) {
    html += '<h4>Evento que originó la alerta</h4><table><tbody>';
    Object.keys(evento).forEach(function (k) {
      html += '<tr><th>' + txt(k.replace(/_/g, ' ')) + '</th><td>' + txt(evento[k]) + '</td></tr>';
    });
    html += '</tbody></table>';
  } else {
    html += '<p class="nota">No se encontró el evento ' + txt(alerta.evento_id) + ' en el conjunto.</p>';
  }
  html += '<p class="nota">Disposición actual: ' + txt(alerta.disposicion) + '</p>';

  el('detalle-cuerpo').innerHTML = html;
  el('detalle').showModal();
}

function arrancar(d) {
  datos = d;
  (datos.eventos || []).forEach(function (e) { porId[e.evento_id] = e; });

  pintarTarjetas(datos.resumen || {});
  pintarFiltroTipos(datos.alertas || []);
  pintarTabla();

  el('generado').textContent = 'datos generados el ' +
    String(datos.generado_en || '').replace('T', ' a las ');

  el('f-tipo').addEventListener('change', pintarTabla);
  el('f-texto').addEventListener('input', pintarTabla);
  el('cerrar').addEventListener('click', function () { el('detalle').close(); });
}

fetch('alertas.json', { cache: 'no-store' })
  .then(function (r) {
    if (!r.ok) throw new Error('HTTP ' + r.status);
    return r.json();
  })
  .then(arrancar)
  .catch(function (err) {
    if (location.protocol === 'file:') {
      mostrarAviso(
        '<strong>Abriste el archivo con doble clic.</strong> El navegador bloquea la lectura de ' +
        '<code>alertas.json</code> con el protocolo <code>file://</code>. Levanta un servidor local:' +
        '<br><br><code>cd web &amp;&amp; python3 -m http.server 8000</code><br><br>' +
        'y abre <code>http://localhost:8000</code>. En Vercel funciona directamente.'
      );
    } else {
      mostrarAviso('<strong>No se pudo cargar <code>alertas.json</code>.</strong> ' +
        'Ejecuta <code>python3 analizador/analizador.py</code> para generarlo. (' + txt(err.message) + ')');
    }
  });
