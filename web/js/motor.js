/* Motor de deteccion y correlacion - lado cliente.
 *
 * IMPORTANTE: esta es una traduccion fiel de analizador/analizador.py.
 * Las dos implementaciones DEBEN producir las mismas alertas sobre el mismo
 * conjunto. La vista "Validacion" lo comprueba en vivo contra la referencia del
 * curso. Si tocas una regla aqui, tocala alla y vuelve a validar.
 *
 * Existe en JS porque el tablero permite cargar un archivo de logs propio y
 * recalcular en el navegador, sin enviar nada a ningun servidor.
 */

export const DISPOSICION_INICIAL = 'Revisar contexto; no confirma incidente';

/* Peso de cada senal, escala 1-3. Multiplicado por la criticidad del activo
 * da la severidad, con la misma escala impacto x exposicion de la rubrica. */
export const PESO_SENAL = {
  'Fallos repetidos': 2,
  'Fuera de horario': 1,
  'Volumen para revisión': 3,
  'Inconsistencia de registro': 2,
};

export const PESO_CRITICIDAD = { Alta: 3, Media: 2, Baja: 1 };

export function etiquetaSeveridad(puntaje) {
  if (puntaje >= 9) return 'Crítica';
  if (puntaje >= 6) return 'Alta';
  if (puntaje >= 3) return 'Media';
  return 'Baja';
}

function aFecha(iso) { return new Date(iso); }
const MIN = 60 * 1000;

/* ------------------------------------------------------------------ */
/* Deteccion: las 4 reglas validadas contra la referencia del curso     */
/* ------------------------------------------------------------------ */
export function detectar(eventos, cfg) {
  const alertas = [];
  const ventanas = new Map();
  const disparadas = new Map();

  const agregar = (e, tipo, motivo) => {
    alertas.push({
      alerta_id: 'AL' + String(alertas.length + 1).padStart(3, '0'),
      evento_id: e.evento_id,
      fecha_hora: e.fecha_hora,
      tipo,
      motivo,
      disposicion: DISPOSICION_INICIAL,
    });
  };

  const ordenados = eventos.slice().sort((a, b) => {
    if (a.fecha_hora !== b.fecha_hora) return a.fecha_hora < b.fecha_hora ? -1 : 1;
    return a.evento_id < b.evento_id ? -1 : a.evento_id > b.evento_id ? 1 : 0;
  });

  for (const e of ordenados) {
    const dt = aFecha(e.fecha_hora);
    const clave = e.origen_ip + '|' + e.destino_ip + '|' + e.usuario_prueba;

    // Regla 1: fallos de autenticacion repetidos en ventana movil.
    if (e.tipo === 'autenticacion' && e.resultado === 'fallo') {
      if (!ventanas.has(clave)) ventanas.set(clave, []);
      const cola = ventanas.get(clave);
      cola.push(dt);
      while (cola.length && dt - cola[0] > cfg.ventana_minutos * MIN) cola.shift();

      const previa = disparadas.get(clave);
      const fueraDeCooldown = !previa || dt - previa > cfg.ventana_minutos * MIN;
      if (cola.length >= cfg.fallos_umbral && fueraDeCooldown) {
        agregar(e, 'Fallos repetidos',
          `${cola.length} fallos en ventana móvil; origen, destino y usuario coincidentes`);
        disparadas.set(clave, dt);
      }
    }

    // Regla 2: acceso exitoso fuera del horario habitual.
    const hora = dt.getHours();
    const fueraDeHorario = !(hora >= cfg.hora_inicio && hora < cfg.hora_fin);
    if (e.tipo === 'autenticacion' && e.resultado === 'exito' && fueraDeHorario) {
      agregar(e, 'Fuera de horario',
        'Acceso exitoso fuera de horario de prueba; revisar cambios autorizados');
    }

    // Regla 3: volumen por encima del umbral de revision.
    if (parseInt(e.bytes, 10) >= cfg.volumen_revision_bytes) {
      agregar(e, 'Volumen para revisión',
        'Volumen supera el umbral de prueba; no confirma extracción de información');
    }

    // Regla 4: evento marcado con R01 que no coincide con su descripcion.
    const coincideR01 = e.destino_ip === '10.60.10.10'
      && parseInt(e.puerto_destino, 10) === 443
      && e.accion === 'allow';
    if (e.regla_id === 'R01' && !coincideR01) {
      agregar(e, 'Inconsistencia de registro',
        'Destino, servicio o acción no coinciden con la descripción simplificada de R01');
    }
  }

  return alertas;
}

/* ------------------------------------------------------------------ */
/* Enriquecimiento: activo, severidad y correlacion con cambios         */
/* ------------------------------------------------------------------ */

/* El activo de una alerta es el destino cuando es interno; si el destino es
 * externo, el activo relevante es el origen (es el que esta sacando datos). */
function activoDeEvento(evento, porIp) {
  if (!evento) return null;
  return porIp.get(evento.destino_ip) || porIp.get(evento.origen_ip) || null;
}

function esExterno(ip, porIp) { return !porIp.has(ip); }

/* Un cambio autorizado cubre un evento solo si coinciden ventana, activo,
 * origen autorizado y usuario. El limite declarado se evalua aparte. */
function cambioQueCubre(evento, cambios, porNombre) {
  if (!evento) return null;
  const t = aFecha(evento.fecha_hora).getTime();
  for (const c of cambios) {
    const dentro = t >= aFecha(c.inicio).getTime() && t <= aFecha(c.fin).getTime();
    if (!dentro) continue;
    const activo = porNombre.get(c.activo);
    if (!activo) continue;
    const destinoEsElActivo = evento.destino_ip === activo.ip_prueba;
    const origenAutorizado = evento.origen_ip === c.origen_autorizado;
    const usuarioCoincide = evento.usuario_prueba === c.usuario_prueba;
    if (destinoEsElActivo && origenAutorizado && usuarioCoincide) return c;
  }
  return null;
}

/* Un cambio en ventana que NO cubre el evento: hay que decir por que no. */
function cambioEnVentana(evento, cambios) {
  if (!evento) return null;
  const t = aFecha(evento.fecha_hora).getTime();
  return cambios.find(c =>
    t >= aFecha(c.inicio).getTime() && t <= aFecha(c.fin).getTime()) || null;
}

export function enriquecer(alertas, eventos, datos) {
  const porId = new Map(eventos.map(e => [e.evento_id, e]));
  const porIp = new Map((datos.inventario || []).map(a => [a.ip_prueba, a]));
  const porNombre = new Map((datos.inventario || []).map(a => [a.nombre_prueba, a]));
  const cambios = datos.cambios_autorizados || [];
  const cfg = datos.parametros || {};

  /* Para la regla "fallos seguidos de exito": indexa los exitos por tupla. */
  const exitos = eventos.filter(e => e.tipo === 'autenticacion' && e.resultado === 'exito');

  return alertas.map(a => {
    const evento = porId.get(a.evento_id) || null;
    const activo = activoDeEvento(evento, porIp);
    const criticidad = activo ? activo.criticidad : 'Media';

    let peso = PESO_SENAL[a.tipo] || 1;
    const notas = [];

    // Escalamiento: fallos repetidos que terminan en un acceso exitoso.
    let seguidoDeExito = false;
    if (a.tipo === 'Fallos repetidos' && evento) {
      const t = aFecha(evento.fecha_hora).getTime();
      seguidoDeExito = exitos.some(x =>
        x.origen_ip === evento.origen_ip &&
        x.destino_ip === evento.destino_ip &&
        x.usuario_prueba === evento.usuario_prueba &&
        aFecha(x.fecha_hora).getTime() > t &&
        aFecha(x.fecha_hora).getTime() - t <= (cfg.ventana_minutos || 10) * MIN);
      if (seguidoDeExito) {
        peso = 3;
        notas.push('Los fallos son seguidos de un acceso exitoso desde el mismo origen y usuario.');
      }
    }

    // Salida hacia un destino fuera del inventario.
    const destinoExterno = evento ? esExterno(evento.destino_ip, porIp) : false;
    if (destinoExterno && a.tipo === 'Volumen para revisión') {
      notas.push('El destino no pertenece al inventario: es una salida hacia Internet.');
    }

    // Correlacion con cambios autorizados.
    const cubre = cambioQueCubre(evento, cambios, porNombre);
    const enVentana = cambioEnVentana(evento, cambios);
    let estado, justificacion;

    if (cubre) {
      estado = 'Descartada';
      justificacion = `Falso positivo descartado: cubierto por el cambio autorizado ${cubre.cambio_id} (${cubre.motivo}), de ${cubre.inicio.slice(11, 16)} a ${cubre.fin.slice(11, 16)}.`;
    } else if (enVentana) {
      estado = 'Abierta';
      justificacion = `Ocurre dentro de la ventana de ${enVentana.cambio_id}, pero NO está cubierta: ${enVentana.limite}.`;
      notas.push(`El cambio ${enVentana.cambio_id} declara: «${enVentana.limite}».`);
    } else {
      estado = 'Abierta';
      justificacion = 'Sin cambio autorizado que la explique.';
    }

    const puntaje = cubre ? 0 : (PESO_CRITICIDAD[criticidad] || 2) * peso;

    return {
      ...a,
      evento,
      activo: activo ? activo.nombre_prueba : '—',
      zona: activo ? activo.zona : '—',
      criticidad,
      peso_senal: peso,
      severidad: puntaje,
      severidad_etiqueta: cubre ? 'Descartada' : etiquetaSeveridad(puntaje),
      estado,
      justificacion,
      cambio_id: cubre ? cubre.cambio_id : null,
      destino_externo: destinoExterno,
      seguido_de_exito: seguidoDeExito,
      notas,
    };
  });
}

/* Pipeline completo: detectar + enriquecer. */
export function analizar(eventos, datos) {
  const cfg = datos.parametros || {};
  return enriquecer(detectar(eventos, cfg), eventos, datos);
}
