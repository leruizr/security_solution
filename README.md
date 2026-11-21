# Monitoreo de eventos y evaluación de vulnerabilidades — Kenworth de la Montaña

Reto **EstudIA** (Alcaldía de Medellín) · Capa 2 · Ciberseguridad básico
Equipo **E-8ZNU «security»** · Bloque 27, salón 303

> **Todos los datos de este repositorio son de prueba.** No representan la
> infraestructura, los registros, las políticas ni las vulnerabilidades reales de
> Kenworth de la Montaña. El ejercicio se trabaja **100 % offline**: solo se leen
> archivos locales. No se escanea ni se conecta a ninguna IP.

## El problema

Kenworth no tiene un proceso estandarizado de monitoreo de eventos y alertas, ni
una evaluación continua de vulnerabilidades. Hoy se revisan ocasionalmente algunos
eventos del firewall, sin un proceso continuo. Eso es lo que hace falta como base
para cualquier plan de hardening.

## La solución propuesta

Tres capas sobre una única fuente de verdad:

1. **Motor de análisis** (`analizador/`) — normaliza los eventos y los correlaciona
   contra el inventario de activos, las políticas del firewall y los cambios
   autorizados. Clasifica cada alerta por severidad.
2. **Tablero de clasificación** (`web/`) — muestra las alertas ordenadas por
   severidad y permite llegar de la alerta a la evidencia cruda en un clic.
3. **Notificación automática** (`n8n/`) — envía correo únicamente cuando aparece una
   alerta crítica, para no generar fatiga de alertas.

## Cómo ejecutarlo

```bash
python3 analizador/analizador.py
```

Requiere **Python 3.9 o superior**. No instala paquetes, no usa internet.

Genera:

| Archivo | Para qué |
|---|---|
| `salidas/alertas.csv` | Revisión manual y plantillas del curso |
| `salidas/resumen.json` | Conteos por tipo |
| `web/alertas.json` | **El contrato de datos** que consume el tablero |

Para ver el tablero en local:

```bash
cd web && python3 -m http.server 8000
```

Y abrir <http://localhost:8000>. Abrirlo con doble clic **no funciona**: el
navegador bloquea la lectura de `alertas.json` bajo el protocolo `file://`.

## Verificación

El analizador reproduce exactamente las 6 alertas de referencia del curso:

```bash
diff salidas/alertas.csv Kenworth_Recursos_de_Prueba/07_Validacion/Referencia_alertas.csv
```

Sin diferencias = la extracción del código no alteró la lógica de detección.

## Estructura

```
.
├── analizador/        Motor de detección en Python (sin dependencias)
├── web/               Tablero estático. Es lo que se despliega en Vercel
├── salidas/           Resultados de cada corrida
├── docs/              Plantillas del curso que el equipo diligencia
├── config/            Configuración local. El archivo real no se versiona
├── n8n/               Diseño y export del flujo de notificación
└── Kenworth_Recursos_de_Prueba/
                       Paquete entregado por el curso. SE DEJA INTACTO:
                       es la fuente de datos y la base de comparación
```

> **Atribución.** La carpeta `Kenworth_Recursos_de_Prueba/` es material didáctico
> entregado por el programa EstudIA; no es autoría del equipo. Se incluye para
> que el análisis sea reproducible. El trabajo propio del equipo es todo lo demás.
> El documento de contexto del proyecto no se publica por contener información
> real de la empresa.

## Despliegue

El tablero se despliega en **Vercel** (plan Hobby, gratuito, uso no comercial).
`vercel.json` ya apunta al directorio `web`.

En producción con logs reales de Kenworth, este tablero se despliega
**on-premise o en la nube privada de la empresa**: los registros de firewall no
deben salir de su perímetro, y la empresa exige acuerdo de confidencialidad.

## Límites reconocidos

- Una alerta es una **señal para revisión**, no un incidente confirmado.
- No prueba intrusión, no atribuye un atacante y no demuestra extracción de datos.
- Las actualizaciones pendientes **no** permiten inferir CVE concretas: faltan
  versiones, boletines y validación técnica.
- Un respaldo «No registrado» significa **ausencia de evidencia**, no que el
  respaldo no exista.
- Un solo día de datos y sin User-ID activo: no se puede asociar una IP a una
  persona ni establecer una tendencia.
- El analizador no interpreta sintaxis de Palo Alto ni sustituye un SIEM.

## Equipo

| Integrante | Rol propuesto |
|---|---|
| Luis Enrique Ruiz Restrepo | Analista de configuración e integración |
| Zara Zapata Mariaca | Analista de eventos |
| Maria Camila Garcia Castrillon | Responsable de activos |
| Juan Daniel Herrera Munoz | Verificador |
| Luis Alexander Ramirez Valencia | Relator |
