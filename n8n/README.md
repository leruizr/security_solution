# Flujo de notificación (n8n)

**Construido y publicado.** Flujo `LOG-SECURITY · Alertas críticas`.

## Cómo funciona

```
POST /webhook/alertas-kenworth
        ↓
  Separar cada alerta
  Descartar las ya notificadas     ← consulta la Data Table
  Juntar las nuevas
        ↓
  ¿Hay alertas nuevas?
        ↓ sí
  Armar el correo (HTML)
  Enviar por Gmail
        ↓
  Registrar como notificadas       ← escribe en la Data Table
```

Los nodos están agrupados en el lienzo en tres bloques: **Deduplicación**,
**Notificación** y **Registro**.

## Decisiones

- **Un solo correo, nunca uno por alerta.** Seis correos serían fatiga de
  alertas: justo el problema que el MVP dice resolver.
- **Doble filtro.** El analizador solo envía severidad 9, y el nodo condicional
  vuelve a comprobarlo. Si alguien descubriera la URL del webhook y enviara
  cualquier cosa, no se dispara un correo.
- **El dedup vive en una Data Table de n8n**, no en un archivo local, para que
  sirva a todo el equipo y no por computador.
- **El registro va después del envío.** Si el correo falla, la alerta no queda
  marcada como notificada y se reintenta. Al revés se perdería.
- **El webhook responde 200 al recibir**, sin esperar al resto. Con la respuesta
  atada al último nodo, una corrida donde todo estaba deduplicado no ejecutaba
  ningún nodo final y devolvía 500 aunque el flujo fuera correcto.
- **Asunto y remitente marcados como datos de prueba**, para que nadie confunda
  un correo de demostración con un incidente real.

## Data Table

`Kenworth alertas notificadas`, con una fila por alerta avisada:
`alerta_id`, `evento_id`, `tipo`, `activo`, `severidad`, `fecha_hora_evento`,
`notificada_en`.

Para repetir el envío en un ensayo: borrar las filas desde n8n y volver a
ejecutar el analizador.

## Enviar desde el analizador

```bash
python3 analizador/analizador.py --notificar
```

El POST se hace con `urllib` de la librería estándar: sin dependencias. Es
opcional y nunca bloquea: si falla la red, se avisa y el análisis sigue siendo
válido. La bandera `--pruebas` usa la URL de test del webhook, que exige pulsar
«Execute workflow» en n8n antes de enviar.

La URL vive en `config/notificaciones.json`, que **no se versiona**: un webhook
es un endpoint abierto y cualquiera con la URL puede dispararlo. Se parte de
`config/notificaciones.ejemplo.json`.

## Antes del pitch

Exportar el flujo desde n8n (**⋯ → Download**) y guardarlo aquí como
`flujo_alertas.json`, **sin credenciales**, para que quede versionado.

**Grabar un video de 20 s del correo llegando.** Si falla el WiFi del salón, se
muestra el video y el pitch sigue.

## Licencia

n8n autohospedado (Community Edition) está bajo *Sustainable Use License*:
gratuito para uso interno. n8n Cloud es de pago con prueba gratuita.
