"""Analizador de eventos de seguridad - Equipo E-8ZNU "security".

Reto Kenworth de la Montana - EstudIA Capa 2 - Ciberseguridad basico.

LIMITES DEL ALCANCE (no quitar):
  - Trabaja 100%% offline: solo LEE archivos locales del paquete de prueba.
  - No escanea, no se conecta a ninguna IP, no modifica configuraciones.
  - Genera SENALES para revision humana. Una alerta no es un incidente.
  - Los datos son de prueba y no representan la infraestructura real de Kenworth.

Punto de partida: 06_Laboratorio/analizador.py del paquete del curso.
La logica de deteccion se mantiene IDENTICA a la original a proposito, para poder
demostrar que esta version reproduce las 6 alertas de 07_Validacion/Referencia_alertas.csv.
Las reglas nuevas se agregan despues, una por una, revalidando en cada paso.

Uso:   python3 analizador/analizador.py
Requiere Python 3.9 o superior. No instala paquetes. No usa internet.
"""

from pathlib import Path
from datetime import datetime, timedelta
from collections import defaultdict, deque
import argparse
import csv
import json
import sys

sys.path.insert(0, str(Path(__file__).resolve().parent))
import severidad
import notificador

# ---------------------------------------------------------------------------
# Rutas. El paquete del curso se deja INTACTO y se usa como unica fuente de
# datos de entrada; este script nunca le escribe nada.
# ---------------------------------------------------------------------------
RAIZ = Path(__file__).resolve().parents[1]
PAQUETE = RAIZ / 'Kenworth_Recursos_de_Prueba'

ENTRADA_EVENTOS = PAQUETE / '02_Datos' / 'eventos_normalizados.csv'
ENTRADA_PARAMETROS = PAQUETE / '03_Configuraciones' / 'parametros_alertas.json'
ENTRADA_INVENTARIO = PAQUETE / '02_Datos' / 'inventario_activos.csv'
ENTRADA_HALLAZGOS = PAQUETE / '02_Datos' / 'hallazgos_iniciales.csv'
ENTRADA_CAMBIOS = PAQUETE / '02_Datos' / 'cambios_autorizados.csv'
ENTRADA_POLITICAS = PAQUETE / '03_Configuraciones' / 'politicas_firewall_prueba.csv'
ENTRADA_SERVIDORES = PAQUETE / '03_Configuraciones' / 'servidores_prueba.json'
ENTRADA_CASOS = PAQUETE / '07_Validacion' / 'Casos_controlados.json'

SALIDAS = RAIZ / 'salidas'
WEB = RAIZ / 'web'
CONFIG_NOTIFICACIONES = RAIZ / 'config' / 'notificaciones.json'

DISPOSICION_INICIAL = 'Revisar contexto; no confirma incidente'


def detectar(eventos, cfg):
    """Aplica las reglas de deteccion y devuelve la lista de alertas."""
    alertas = []
    ventanas = defaultdict(deque)
    disparadas = {}

    def alertar(evento, tipo, motivo):
        alertas.append({
            'alerta_id': f'AL{len(alertas) + 1:03}',
            'evento_id': evento['evento_id'],
            'fecha_hora': evento['fecha_hora'],
            'tipo': tipo,
            'motivo': motivo,
            'disposicion': DISPOSICION_INICIAL,
            'origen_regla': 'base',
        })

    for e in sorted(eventos, key=lambda x: (x['fecha_hora'], x['evento_id'])):
        dt = datetime.fromisoformat(e['fecha_hora'])
        clave = (e['origen_ip'], e['destino_ip'], e['usuario_prueba'])

        # Regla 1: fallos de autenticacion repetidos en ventana movil.
        if e['tipo'] == 'autenticacion' and e['resultado'] == 'fallo':
            cola = ventanas[clave]
            cola.append(dt)
            while cola and dt - cola[0] > timedelta(minutes=cfg['ventana_minutos']):
                cola.popleft()
            ya_disparo = clave in disparadas
            fuera_de_cooldown = (
                not ya_disparo
                or dt - disparadas[clave] > timedelta(minutes=cfg['ventana_minutos'])
            )
            if len(cola) >= cfg['fallos_umbral'] and fuera_de_cooldown:
                alertar(
                    e,
                    'Fallos repetidos',
                    f'{len(cola)} fallos en ventana móvil; origen, destino y usuario coincidentes',
                )
                disparadas[clave] = dt

        # Regla 2: acceso exitoso fuera del horario habitual de prueba.
        fuera_de_horario = not cfg['hora_inicio'] <= dt.hour < cfg['hora_fin']
        if e['tipo'] == 'autenticacion' and e['resultado'] == 'exito' and fuera_de_horario:
            alertar(
                e,
                'Fuera de horario',
                'Acceso exitoso fuera de horario de prueba; revisar cambios autorizados',
            )

        # Regla 3: volumen observado por encima del umbral de revision.
        if int(e['bytes']) >= cfg['volumen_revision_bytes']:
            alertar(
                e,
                'Volumen para revisión',
                'Volumen supera el umbral de prueba; no confirma extracción de información',
            )

        # Regla 4: evento registrado con R01 que no coincide con su descripcion.
        coincide_con_r01 = (
            e['destino_ip'] == '10.60.10.10'
            and int(e['puerto_destino']) == 443
            and e['accion'] == 'allow'
        )
        if e['regla_id'] == 'R01' and not coincide_con_r01:
            alertar(
                e,
                'Inconsistencia de registro',
                'Destino, servicio o acción no coinciden con la descripción simplificada de R01',
            )

    return alertas

def detectar_ampliadas(eventos, cfg, inventario, politicas, desde=0):
    """Reglas que el analizador original del curso NO trae.

    Van aparte de detectar() a proposito: asi las 4 reglas base siguen
    reproduciendo byte a byte 07_Validacion/Referencia_alertas.csv, y la mejora
    del equipo se puede mostrar y medir por separado. Los identificadores de las
    alertas base no se mueven, lo que importa porque ya estan citados en el
    expediente y en la Data Table de alertas notificadas.
    """
    alertas = []
    por_ip = {a['ip_prueba']: a for a in inventario}
    criticos = {a['ip_prueba'] for a in inventario if a['criticidad'] == 'Alta'}
    sin_registro = {p['regla_id'] for p in politicas if p['registro'] == 'no'}

    def alertar(evento, tipo, motivo):
        alertas.append({
            'evento_id': evento['evento_id'],
            'fecha_hora': evento['fecha_hora'],
            'tipo': tipo,
            'motivo': motivo,
            'disposicion': DISPOSICION_INICIAL,
            'origen_regla': 'ampliada',
        })

    def nombre(ip):
        activo = por_ip.get(ip)
        return activo['nombre_prueba'] if activo else ip

    ordenados = sorted(eventos, key=lambda x: (x['fecha_hora'], x['evento_id']))

    # Regla 5: denegaciones repetidas desde fuera del inventario hacia un activo
    # critico. El firewall las bloqueo, asi que no hubo acceso; pero el patron
    # (muchos intentos, varios puertos, un solo origen) merece revision.
    ventanas = defaultdict(deque)
    puertos = defaultdict(set)
    disparadas = {}
    for e in ordenados:
        if e['accion'] != 'deny':
            continue
        if e['origen_ip'] in por_ip:          # origen interno: no viene de Internet
            continue
        if e['destino_ip'] not in criticos:
            continue

        dt = datetime.fromisoformat(e['fecha_hora'])
        clave = (e['origen_ip'], e['destino_ip'])
        cola = ventanas[clave]
        cola.append(dt)
        puertos[clave].add(str(e['puerto_destino']))
        while cola and dt - cola[0] > timedelta(minutes=cfg['ventana_minutos']):
            cola.popleft()

        previa = disparadas.get(clave)
        fuera_de_cooldown = (
            previa is None
            or dt - previa > timedelta(minutes=cfg['ventana_minutos'])
        )
        if len(cola) >= cfg['fallos_umbral'] and fuera_de_cooldown:
            lista = ', '.join(sorted(puertos[clave], key=int))
            alertar(
                e,
                'Denegaciones repetidas',
                f'{len(cola)} intentos bloqueados en ventana móvil desde '
                f'{e["origen_ip"]}, que no está en el inventario, hacia '
                f'{nombre(e["destino_ip"])}. Puertos probados: {lista}. '
                f'El firewall los negó: no hubo acceso.',
            )
            disparadas[clave] = dt

    # Regla 6: uso efectivo de una excepcion que la politica declara sin
    # registro. Una sola alerta por regla, no una por evento: ocho avisos del
    # mismo problema serian fatiga de alertas.
    usos = defaultdict(list)
    for e in ordenados:
        if e['regla_id'] in sin_registro:
            usos[e['regla_id']].append(e)

    for regla_id in sorted(usos):
        grupo = usos[regla_id]
        destinos = ', '.join(sorted({nombre(g['destino_ip']) for g in grupo}))
        politica = next((p for p in politicas if p['regla_id'] == regla_id), None)
        observacion = politica['observacion'] if politica else ''
        alertar(
            grupo[0],
            'Excepción sin registro',
            f'{len(grupo)} eventos pasaron por {regla_id}, que la política '
            f'declara sin registro ({observacion.lower()}). Destinos: {destinos}. '
            f'Estos accesos no quedan en ninguna auditoría posterior.',
        )

    # Numeracion continua, despues de las base, en orden cronologico.
    alertas.sort(key=lambda a: (a['fecha_hora'], a['evento_id']))
    for i, a in enumerate(alertas):
        a['alerta_id'] = f'AL{desde + i + 1:03}'
    return alertas


def cargar_csv(ruta):
    """Lee un CSV del paquete. Todos vienen en UTF-8 con BOM."""
    with ruta.open(encoding='utf-8-sig', newline='') as f:
        return list(csv.DictReader(f))


def cargar_eventos(ruta):
    return cargar_csv(ruta)


def escribir_csv(ruta, filas, campos):
    """Escribe solo las columnas pedidas; ignora los campos de mas."""
    with ruta.open('w', encoding='utf-8-sig', newline='') as f:
        escritor = csv.DictWriter(f, fieldnames=campos, extrasaction='ignore')
        escritor.writeheader()
        escritor.writerows(filas)


def run(notificar=False, pruebas=False):
    if not ENTRADA_EVENTOS.exists():
        raise SystemExit(
            f'No se encontro el archivo de eventos en:\n  {ENTRADA_EVENTOS}\n'
            'Verifica que la carpeta Kenworth_Recursos_de_Prueba este en la raiz del repositorio.'
        )

    eventos = cargar_eventos(ENTRADA_EVENTOS)
    cfg = json.loads(ENTRADA_PARAMETROS.read_text(encoding='utf-8'))
    inventario = cargar_csv(ENTRADA_INVENTARIO)
    cambios = cargar_csv(ENTRADA_CAMBIOS)

    politicas = cargar_csv(ENTRADA_POLITICAS)

    # Las 4 reglas del curso primero, para que sus identificadores no cambien
    # nunca; las 2 del equipo despues, numeradas a continuacion.
    base = detectar(eventos, cfg)
    ampliadas = detectar_ampliadas(eventos, cfg, inventario, politicas, desde=len(base))
    alertas = base + ampliadas

    enriquecidas = severidad.enriquecer(alertas, eventos, inventario, cambios, cfg)
    criticas = severidad.criticas(enriquecidas)

    SALIDAS.mkdir(exist_ok=True)
    WEB.mkdir(exist_ok=True)

    por_tipo = defaultdict(int)
    for a in alertas:
        por_tipo[a['tipo']] += 1

    resumen = {
        'eventos': len(eventos),
        'alertas': len(alertas),
        'alertas_base': len(base),
        'alertas_ampliadas': len(ampliadas),
        'por_tipo': dict(por_tipo),
        'nota': 'Datos de prueba. La cantidad de alertas no equivale a incidentes.',
    }

    # Dos CSV distintos, a proposito:
    #   alertas_base.csv  -> SOLO las 4 reglas del curso. Es el que se compara
    #                        con 07_Validacion/Referencia_alertas.csv y tiene que
    #                        salir identico, sin importar cuantas reglas agreguemos.
    #   alertas.csv       -> el producto del equipo, con todas las reglas.
    # Ambos conservan las 6 columnas del esquema del curso; el enriquecimiento
    # (activo, severidad, correlacion) viaja en el JSON.
    campos = ['alerta_id', 'evento_id', 'fecha_hora', 'tipo', 'motivo', 'disposicion']
    escribir_csv(SALIDAS / 'alertas_base.csv', base, campos)
    escribir_csv(SALIDAS / 'alertas.csv', alertas, campos)
    (SALIDAS / 'resumen.json').write_text(
        json.dumps(resumen, ensure_ascii=False, indent=2), encoding='utf-8'
    )

    # Contrato de datos que consume el tablero web (y mas adelante n8n).
    # Todo sale de los archivos del curso: el tablero NUNCA tiene datos escritos
    # a mano. Si un numero cambia en el CSV, cambia solo en el tablero.
    contrato = {
        'generado_en': datetime.now().isoformat(timespec='seconds'),
        'origen_datos': 'Kenworth_Recursos_de_Prueba (datos de prueba del curso)',
        'parametros': cfg,
        'inventario': inventario,
        'hallazgos': cargar_csv(ENTRADA_HALLAZGOS),
        'cambios_autorizados': cambios,
        'politicas': politicas,
        'servidores': json.loads(ENTRADA_SERVIDORES.read_text(encoding='utf-8')),
        'casos_controlados': json.loads(ENTRADA_CASOS.read_text(encoding='utf-8')),
        'resumen': resumen,
        'alertas': enriquecidas,
        # Eventos crudos para que el tablero pueda mostrar la EVIDENCIA detras de
        # cada alerta en un clic. La guia lo pide de forma explicita: otro equipo
        # debe poder llegar del alerta al evento que la origino.
        'eventos': eventos,
    }
    (WEB / 'alertas.json').write_text(
        json.dumps(contrato, ensure_ascii=False, indent=2), encoding='utf-8'
    )

    print(json.dumps(resumen, ensure_ascii=False, indent=2))
    print(f'\nEscrito: {SALIDAS / "alertas_base.csv"} (4 reglas del curso, {len(base)} alertas)')
    print(f'Escrito: {SALIDAS / "alertas.csv"} ({len(alertas)} alertas en total)')
    print(f'Escrito: {SALIDAS / "resumen.json"}')
    print(f'Escrito: {WEB / "alertas.json"}')

    print(f'\nAlertas criticas abiertas (severidad >= {severidad.SEVERIDAD_CRITICA}): {len(criticas)}')
    for a in criticas:
        print(f'  {a["alerta_id"]} · {a["evento_id"]} · {a["tipo"]} · '
              f'{a["activo"]} · severidad {a["severidad"]}')

    if notificar:
        cfg_notif = notificador.cargar_config(CONFIG_NOTIFICACIONES)
        if cfg_notif is None:
            print('\n[notificador] desactivado. Copia config/notificaciones.ejemplo.json '
                  'a config/notificaciones.json, pon la URL y marca "activo": true.')
        else:
            contexto = dict(resumen)
            contexto['generado_en'] = contrato['generado_en']
            contexto['dataset'] = 'Laboratorio Kenworth'
            url = cfg_notif.get('webhook_url_pruebas') if pruebas else None
            n, mensaje = notificador.notificar(criticas, cfg_notif, contexto, url=url)
            print(f'\n[notificador] {mensaje}')

    return resumen


if __name__ == '__main__':
    parser = argparse.ArgumentParser(
        description='Analiza los eventos de prueba y genera alertas clasificadas.')
    parser.add_argument('--notificar', action='store_true',
                        help='envia las alertas criticas nuevas al webhook de n8n')
    parser.add_argument('--pruebas', action='store_true',
                        help='usa la URL de pruebas del webhook en vez de la de produccion')
    args = parser.parse_args()
    run(notificar=args.notificar, pruebas=args.pruebas)
