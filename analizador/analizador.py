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
import csv
import json

# ---------------------------------------------------------------------------
# Rutas. El paquete del curso se deja INTACTO y se usa como unica fuente de
# datos de entrada; este script nunca le escribe nada.
# ---------------------------------------------------------------------------
RAIZ = Path(__file__).resolve().parents[1]
PAQUETE = RAIZ / 'Kenworth_Recursos_de_Prueba'

ENTRADA_EVENTOS = PAQUETE / '02_Datos' / 'eventos_normalizados.csv'
ENTRADA_PARAMETROS = PAQUETE / '03_Configuraciones' / 'parametros_alertas.json'

SALIDAS = RAIZ / 'salidas'
WEB = RAIZ / 'web'

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

# ---------------------------------------------------------------------------
# PENDIENTE (MVP del equipo). Cada regla se agrega y se revalida por separado:
#   5. Enriquecer cada alerta con el inventario: activo, zona y criticidad.
#   6. Reconocer CH01 (cambios_autorizados.csv) para cerrar lo autorizado.
#   7. Detectar "fallos seguidos de exito" como una sola alerta correlacionada.
#   8. Detectar denegaciones repetidas desde Internet hacia un activo critico.
#   9. Alertar por uso de R02, la excepcion que no registra eventos.
#  10. Calcular severidad = criticidad_activo x peso_senal (escala 1-3 x 1-3).
# ---------------------------------------------------------------------------


def cargar_eventos(ruta):
    """Lee el CSV de eventos. El paquete usa UTF-8 con BOM."""
    with ruta.open(encoding='utf-8-sig', newline='') as f:
        return list(csv.DictReader(f))


def escribir_csv(ruta, filas, campos):
    with ruta.open('w', encoding='utf-8-sig', newline='') as f:
        escritor = csv.DictWriter(f, fieldnames=campos)
        escritor.writeheader()
        escritor.writerows(filas)


def run():
    if not ENTRADA_EVENTOS.exists():
        raise SystemExit(
            f'No se encontro el archivo de eventos en:\n  {ENTRADA_EVENTOS}\n'
            'Verifica que la carpeta Kenworth_Recursos_de_Prueba este en la raiz del repositorio.'
        )

    eventos = cargar_eventos(ENTRADA_EVENTOS)
    cfg = json.loads(ENTRADA_PARAMETROS.read_text(encoding='utf-8'))
    alertas = detectar(eventos, cfg)

    SALIDAS.mkdir(exist_ok=True)
    WEB.mkdir(exist_ok=True)

    por_tipo = defaultdict(int)
    for a in alertas:
        por_tipo[a['tipo']] += 1

    resumen = {
        'eventos': len(eventos),
        'alertas': len(alertas),
        'por_tipo': dict(por_tipo),
        'nota': 'Datos de prueba. La cantidad de alertas no equivale a incidentes.',
    }

    # Salidas para revision manual y para las plantillas del curso.
    escribir_csv(
        SALIDAS / 'alertas.csv',
        alertas,
        ['alerta_id', 'evento_id', 'fecha_hora', 'tipo', 'motivo', 'disposicion'],
    )
    (SALIDAS / 'resumen.json').write_text(
        json.dumps(resumen, ensure_ascii=False, indent=2), encoding='utf-8'
    )

    # Contrato de datos que consume el tablero web (y mas adelante n8n).
    contrato = {
        'generado_en': datetime.now().isoformat(timespec='seconds'),
        'origen_datos': 'Kenworth_Recursos_de_Prueba (datos de prueba del curso)',
        'parametros': cfg,
        'resumen': resumen,
        'alertas': alertas,
        # Eventos crudos para que el tablero pueda mostrar la EVIDENCIA detras de
        # cada alerta en un clic. La guia lo pide de forma explicita: otro equipo
        # debe poder llegar del alerta al evento que la origino.
        'eventos': eventos,
    }
    (WEB / 'alertas.json').write_text(
        json.dumps(contrato, ensure_ascii=False, indent=2), encoding='utf-8'
    )

    print(json.dumps(resumen, ensure_ascii=False, indent=2))
    print(f'\nEscrito: {SALIDAS / "alertas.csv"}')
    print(f'Escrito: {SALIDAS / "resumen.json"}')
    print(f'Escrito: {WEB / "alertas.json"}')
    return resumen


if __name__ == '__main__':
    run()
