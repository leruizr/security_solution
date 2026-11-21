/* Lectura de archivos de logs en el navegador.
 *
 * El archivo se lee con FileReader y NUNCA sale del equipo: no hay subida,
 * no hay servidor, no hay peticion de red. Eso importa porque el dia que esto
 * se use con logs reales, los registros no deben salir del perimetro.
 */

export const COLUMNAS_MINIMAS = ['evento_id', 'fecha_hora', 'origen_ip', 'destino_ip'];

const ALIAS = {
  id: 'evento_id', event_id: 'evento_id',
  timestamp: 'fecha_hora', fecha: 'fecha_hora', time: 'fecha_hora',
  src: 'origen_ip', source_ip: 'origen_ip', origen: 'origen_ip',
  dst: 'destino_ip', destination_ip: 'destino_ip', destino: 'destino_ip',
  puerto: 'puerto_destino', dport: 'puerto_destino', port: 'puerto_destino',
  action: 'accion', rule: 'regla_id', regla: 'regla_id',
  user: 'usuario_prueba', usuario: 'usuario_prueba',
  result: 'resultado', type: 'tipo', bytes_total: 'bytes',
};

function normalizarClave(k) {
  const limpia = String(k).trim().toLowerCase().replace(/\s+/g, '_');
  return ALIAS[limpia] || limpia;
}

/* Parser de CSV que respeta comillas y comas dentro de campos. */
function dividirLinea(linea) {
  const campos = [];
  let actual = '';
  let enComillas = false;
  for (let i = 0; i < linea.length; i++) {
    const c = linea[i];
    if (c === '"') {
      if (enComillas && linea[i + 1] === '"') { actual += '"'; i++; }
      else enComillas = !enComillas;
    } else if (c === ',' && !enComillas) {
      campos.push(actual); actual = '';
    } else {
      actual += c;
    }
  }
  campos.push(actual);
  return campos;
}

export function parsearCSV(texto) {
  const limpio = texto.replace(/^﻿/, '');           // quita el BOM
  const lineas = limpio.split(/\r?\n/).filter(l => l.trim() !== '');
  if (!lineas.length) return [];
  const cabecera = dividirLinea(lineas[0]).map(normalizarClave);
  return lineas.slice(1).map(l => {
    const campos = dividirLinea(l);
    const fila = {};
    cabecera.forEach((col, i) => { fila[col] = (campos[i] ?? '').trim(); });
    return fila;
  });
}

export function parsearJSONL(texto) {
  return texto.split(/\r?\n/)
    .filter(l => l.trim() !== '')
    .map(l => JSON.parse(l));
}

export function parsearJSON(texto) {
  const d = JSON.parse(texto);
  if (Array.isArray(d)) return d;
  if (Array.isArray(d.eventos)) return d.eventos;          // nuestro propio contrato
  throw new Error('El JSON debe ser un arreglo de eventos o traer una clave "eventos".');
}

/* Normaliza claves y tipos para que el motor reciba siempre la misma forma. */
function normalizarEventos(filas) {
  return filas.map(f => {
    const e = {};
    Object.keys(f).forEach(k => { e[normalizarClave(k)] = f[k]; });
    return {
      evento_id: String(e.evento_id ?? ''),
      fecha_hora: String(e.fecha_hora ?? ''),
      zona_horaria: e.zona_horaria ?? '',
      tipo: String(e.tipo ?? 'trafico'),
      origen_ip: String(e.origen_ip ?? ''),
      destino_ip: String(e.destino_ip ?? ''),
      puerto_destino: String(e.puerto_destino ?? '0'),
      accion: String(e.accion ?? ''),
      regla_id: String(e.regla_id ?? ''),
      usuario_prueba: String(e.usuario_prueba ?? '-'),
      resultado: String(e.resultado ?? '-'),
      bytes: String(e.bytes ?? '0'),
    };
  });
}

export function validar(filas) {
  if (!filas.length) {
    return { ok: false, mensaje: 'El archivo no contiene filas de datos.' };
  }
  const presentes = Object.keys(filas[0]);
  const faltan = COLUMNAS_MINIMAS.filter(c => !presentes.includes(c));
  if (faltan.length) {
    return {
      ok: false,
      mensaje: `Formato no compatible: faltan las columnas ${faltan.join(', ')}. ` +
               'Asegúrate de usar logs normalizados con el esquema del ejercicio.',
    };
  }
  const conFecha = filas.filter(f => f.fecha_hora && !isNaN(new Date(f.fecha_hora)));
  if (!conFecha.length) {
    return { ok: false, mensaje: 'Ninguna fila tiene una fecha legible en formato ISO (2026-11-20T09:00:00).' };
  }
  return { ok: true };
}

/* Punto de entrada: recibe un File y devuelve los eventos normalizados. */
export function leerArchivo(file) {
  return new Promise((resolve, reject) => {
    const nombre = file.name.toLowerCase();
    const lector = new FileReader();

    lector.onerror = () => reject(new Error('No se pudo leer el archivo.'));
    lector.onload = () => {
      try {
        const texto = String(lector.result);
        let filas;
        if (nombre.endsWith('.csv')) filas = parsearCSV(texto);
        else if (nombre.endsWith('.jsonl') || nombre.endsWith('.ndjson')) filas = parsearJSONL(texto);
        else if (nombre.endsWith('.json')) filas = parsearJSON(texto);
        else return reject(new Error('Extensión no admitida. Usa .csv, .json o .jsonl.'));

        const eventos = normalizarEventos(filas);
        const v = validar(eventos);
        if (!v.ok) return reject(new Error(v.mensaje));
        resolve(eventos);
      } catch (err) {
        reject(new Error('No se pudo interpretar el archivo: ' + err.message));
      }
    };
    lector.readAsText(file, 'utf-8');
  });
}
