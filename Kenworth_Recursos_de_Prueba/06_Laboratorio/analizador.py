"""Laboratorio offline: solo lee archivos locales y genera salidas de prueba."""
from pathlib import Path
from datetime import datetime,timedelta
from collections import defaultdict,deque
import csv,json

def detectar(events,cfg):
    out=[];windows=defaultdict(deque);triggered={}
    def alert(e,t,reason):out.append({'alerta_id':f'AL{len(out)+1:03}','evento_id':e['evento_id'],'fecha_hora':e['fecha_hora'],'tipo':t,'motivo':reason,'disposicion':'Revisar contexto; no confirma incidente'})
    for e in sorted(events,key=lambda x:(x['fecha_hora'],x['evento_id'])):
        dt=datetime.fromisoformat(e['fecha_hora']);key=(e['origen_ip'],e['destino_ip'],e['usuario_prueba'])
        if e['tipo']=='autenticacion' and e['resultado']=='fallo':
            q=windows[key];q.append(dt)
            while q and dt-q[0]>timedelta(minutes=cfg['ventana_minutos']):q.popleft()
            if len(q)>=cfg['fallos_umbral'] and (key not in triggered or dt-triggered[key]>timedelta(minutes=cfg['ventana_minutos'])):
                alert(e,'Fallos repetidos',f'{len(q)} fallos en ventana móvil; origen, destino y usuario coincidentes');triggered[key]=dt
        if e['tipo']=='autenticacion' and e['resultado']=='exito' and not cfg['hora_inicio']<=dt.hour<cfg['hora_fin']:
            alert(e,'Fuera de horario','Acceso exitoso fuera de horario de prueba; revisar cambios autorizados')
        if int(e['bytes'])>=cfg['volumen_revision_bytes']:
            alert(e,'Volumen para revisión','Volumen supera el umbral de prueba; no confirma extracción de información')
        if e['regla_id']=='R01' and not(e['destino_ip']=='10.60.10.10' and int(e['puerto_destino'])==443 and e['accion']=='allow'):
            alert(e,'Inconsistencia de registro','Destino, servicio o acción no coinciden con la descripción simplificada de R01')
    return out

def run(root):
    with (root/'02_Datos/eventos_normalizados.csv').open(encoding='utf-8-sig',newline='') as f:events=list(csv.DictReader(f))
    cfg=json.loads((root/'03_Configuraciones/parametros_alertas.json').read_text(encoding='utf-8'))
    alerts=detectar(events,cfg);dest=root/'Salidas';dest.mkdir(exist_ok=True)
    fields=['alerta_id','evento_id','fecha_hora','tipo','motivo','disposicion']
    with (dest/'alertas.csv').open('w',encoding='utf-8-sig',newline='') as f:
        w=csv.DictWriter(f,fieldnames=fields);w.writeheader();w.writerows(alerts)
    by=defaultdict(int)
    for a in alerts:by[a['tipo']]+=1
    summary={'eventos':len(events),'alertas':len(alerts),'por_tipo':dict(by),'nota':'Datos de prueba. La cantidad de alertas no equivale a incidentes.'}
    (dest/'resumen.json').write_text(json.dumps(summary,ensure_ascii=False,indent=2),encoding='utf-8')
    print(json.dumps(summary,ensure_ascii=False,indent=2));return summary

if __name__=='__main__':run(Path(__file__).resolve().parents[1])
