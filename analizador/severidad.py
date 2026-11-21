"""Enriquecimiento de alertas: activo, correlacion con cambios y severidad.

Es la traduccion fiel de web/js/motor.js (funcion `enriquecer`). Las dos
implementaciones DEBEN coincidir: la vista Validacion del tablero lo comprueba.
Si cambias una regla aqui, cambiala alla y vuelve a validar.

severidad = criticidad del activo (1 a 3) x peso de la senal (1 a 3)
  9 = Critica (unica que dispara correo) | 6 = Alta | 3 a 4 = Media | 1 a 2 = Baja
Una alerta cubierta por un cambio autorizado se descarta con justificacion.
"""

from datetime import datetime, timedelta

PESO_SENAL = {
    'Fallos repetidos': 2,
    'Fuera de horario': 1,
    'Volumen para revisión': 3,
    'Inconsistencia de registro': 2,
    'Escaneo de puertos': 2,
    'Escaneo distribuido de puertos': 2,
    'Denegaciones repetidas': 2,
    'Excepción sin registro': 2,
}

PESO_CRITICIDAD = {'Alta': 3, 'Media': 2, 'Baja': 1}

SEVERIDAD_CRITICA = 9


def etiqueta_severidad(puntaje):
    if puntaje >= 9:
        return 'Crítica'
    if puntaje >= 6:
        return 'Alta'
    if puntaje >= 3:
        return 'Media'
    return 'Baja'


def _fecha(iso):
    return datetime.fromisoformat(iso)


def _activo_de_evento(evento, por_ip):
    if not evento:
        return None
    return por_ip.get(evento['destino_ip']) or por_ip.get(evento['origen_ip'])


def _cambio_que_cubre(evento, cambios, por_nombre):
    """Un cambio cubre un evento solo si coinciden ventana, activo, origen
    autorizado y usuario. Coincidir solo en la hora no es una autorizacion."""
    if not evento:
        return None
    t = _fecha(evento['fecha_hora'])
    for c in cambios:
        if not (_fecha(c['inicio']) <= t <= _fecha(c['fin'])):
            continue
        activo = por_nombre.get(c['activo'])
        if not activo:
            continue
        if (evento['destino_ip'] == activo['ip_prueba']
                and evento['origen_ip'] == c['origen_autorizado']
                and evento['usuario_prueba'] == c['usuario_prueba']):
            return c
    return None


def _cambio_en_ventana(evento, cambios):
    if not evento:
        return None
    t = _fecha(evento['fecha_hora'])
    for c in cambios:
        if _fecha(c['inicio']) <= t <= _fecha(c['fin']):
            return c
    return None


def enriquecer(alertas, eventos, inventario, cambios, cfg):
    por_id = {e['evento_id']: e for e in eventos}
    por_ip = {a['ip_prueba']: a for a in inventario}
    por_nombre = {a['nombre_prueba']: a for a in inventario}
    ventana = timedelta(minutes=cfg.get('ventana_minutos', 10))

    exitos = [e for e in eventos
              if e['tipo'] == 'autenticacion' and e['resultado'] == 'exito']

    resultado = []
    for a in alertas:
        evento = por_id.get(a['evento_id'])
        activo = _activo_de_evento(evento, por_ip)
        criticidad = activo['criticidad'] if activo else 'Media'

        peso = PESO_SENAL.get(a['tipo'], 1)
        notas = []

        # Escalamiento: fallos repetidos que terminan en un acceso exitoso.
        seguido_de_exito = False
        if a['tipo'] == 'Fallos repetidos' and evento:
            t = _fecha(evento['fecha_hora'])
            for x in exitos:
                tx = _fecha(x['fecha_hora'])
                if (x['origen_ip'] == evento['origen_ip']
                        and x['destino_ip'] == evento['destino_ip']
                        and x['usuario_prueba'] == evento['usuario_prueba']
                        and t < tx <= t + ventana):
                    seguido_de_exito = True
                    break
            if seguido_de_exito:
                peso = 3
                notas.append('Los fallos son seguidos de un acceso exitoso '
                             'desde el mismo origen y usuario.')

        destino_externo = bool(evento) and evento['destino_ip'] not in por_ip
        if destino_externo and a['tipo'] == 'Volumen para revisión':
            notas.append('El destino no pertenece al inventario: '
                         'es una salida hacia Internet.')

        cubre = _cambio_que_cubre(evento, cambios, por_nombre)
        en_ventana = _cambio_en_ventana(evento, cambios)

        if cubre:
            estado = 'Descartada'
            justificacion = (
                f"Falso positivo descartado: cubierto por el cambio autorizado "
                f"{cubre['cambio_id']} ({cubre['motivo']}), de "
                f"{cubre['inicio'][11:16]} a {cubre['fin'][11:16]}.")
        elif en_ventana:
            estado = 'Abierta'
            justificacion = (
                f"Ocurre dentro de la ventana de {en_ventana['cambio_id']}, "
                f"pero NO está cubierta: {en_ventana['limite']}.")
            notas.append(f"El cambio {en_ventana['cambio_id']} declara: "
                         f"«{en_ventana['limite']}».")
        else:
            estado = 'Abierta'
            justificacion = 'Sin cambio autorizado que la explique.'

        puntaje = 0 if cubre else PESO_CRITICIDAD.get(criticidad, 2) * peso

        enriquecida = dict(a)
        enriquecida.update({
            'activo': activo['nombre_prueba'] if activo else '—',
            'zona': activo['zona'] if activo else '—',
            'criticidad': criticidad,
            'peso_senal': peso,
            'severidad': puntaje,
            'severidad_etiqueta': 'Descartada' if cubre else etiqueta_severidad(puntaje),
            'estado': estado,
            'justificacion': justificacion,
            'cambio_id': cubre['cambio_id'] if cubre else None,
            'destino_externo': destino_externo,
            'seguido_de_exito': seguido_de_exito,
            'notas': notas,
        })
        resultado.append(enriquecida)

    return resultado


def criticas(alertas_enriquecidas, minimo=SEVERIDAD_CRITICA):
    return [a for a in alertas_enriquecidas
            if a['estado'] == 'Abierta' and a['severidad'] >= minimo]
