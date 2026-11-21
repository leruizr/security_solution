"""Envio de alertas criticas al webhook de n8n.

Tres reglas que no se tocan:
  1. Es OPCIONAL. El analizador funciona igual sin internet y sin este modulo.
  2. Nunca bloquea. Si el envio falla, se avisa y el analisis sigue siendo valido.
  3. No decide que es nuevo. El control de lo ya notificado vive en la Data Table
     "Kenworth alertas notificadas" dentro de n8n, para que sea del equipo y no
     de una sola maquina. Aqui se envian TODAS las criticas y n8n descarta las
     repetidas antes de enviar el correo.

Solo usa la libreria estandar: urllib. No hay que instalar nada.
"""

import json
import urllib.request
import urllib.error

TIEMPO_LIMITE = 15  # segundos


def cargar_config(ruta):
    """Lee config/notificaciones.json. Si no existe, el envio queda desactivado."""
    if not ruta.exists():
        return None
    try:
        cfg = json.loads(ruta.read_text(encoding='utf-8'))
    except json.JSONDecodeError as e:
        print(f'  [notificador] {ruta.name} no es JSON valido: {e}')
        return None
    if not cfg.get('activo'):
        return None
    if not str(cfg.get('webhook_url', '')).startswith('http'):
        print('  [notificador] falta webhook_url en la configuracion.')
        return None
    return cfg


def construir_carga(criticas, cfg, contexto):
    """Arma el cuerpo JSON que espera el webhook."""
    return {
        'dataset': contexto.get('dataset', 'Laboratorio Kenworth'),
        'generado_en': contexto.get('generado_en', ''),
        'total_eventos': contexto.get('eventos', 0),
        'total_alertas': contexto.get('alertas', 0),
        'asunto_prefijo': cfg.get('asunto_prefijo', '[DATOS DE PRUEBA]'),
        'destinatarios': cfg.get('destinatarios', []),
        'criticas': [
            {
                'alerta_id': a['alerta_id'],
                'evento_id': a['evento_id'],
                'fecha_hora': a['fecha_hora'],
                'tipo': a['tipo'],
                'motivo': a['motivo'],
                'activo': a['activo'],
                'zona': a['zona'],
                'criticidad': a['criticidad'],
                'severidad': a['severidad'],
                'justificacion': a['justificacion'],
            }
            for a in criticas
        ],
    }


def notificar(criticas, cfg, contexto, url=None):
    """Envia las alertas criticas al webhook. Devuelve (enviadas, mensaje)."""
    if not criticas:
        return 0, 'no hay alertas criticas que notificar'

    destino = url or cfg['webhook_url']
    cuerpo = json.dumps(construir_carga(criticas, cfg, contexto),
                        ensure_ascii=False).encode('utf-8')

    peticion = urllib.request.Request(
        destino,
        data=cuerpo,
        headers={'Content-Type': 'application/json; charset=utf-8'},
        method='POST',
    )

    try:
        with urllib.request.urlopen(peticion, timeout=TIEMPO_LIMITE) as r:
            codigo = r.status
    except urllib.error.HTTPError as e:
        if e.code == 404:
            return 0, ('el webhook respondio 404. Si usas la URL de pruebas, '
                       'pulsa "Execute workflow" en n8n antes de enviar; '
                       'si usas la de produccion, publica el flujo.')
        return 0, f'el webhook respondio {e.code}: {e.reason}'
    except urllib.error.URLError as e:
        return 0, f'no se pudo contactar el webhook: {e.reason}'
    except OSError as e:
        return 0, f'error de red: {e}'

    if codigo >= 300:
        return 0, f'el webhook respondio {codigo}'

    ids = ', '.join(a['alerta_id'] for a in criticas)
    return len(criticas), (f'enviadas {len(criticas)} alerta(s) al webhook ({ids}). '
                           'n8n descarta las que ya estaban en la Data Table.')
