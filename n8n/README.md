# Flujo de notificación (n8n)

Pendiente de construir. Va **al final**, después de que el analizador y el tablero estén cerrados.

## Diseño acordado

```
analizador.py  --POST-->  Webhook (n8n)  -->  Filter (severidad >= 9)  -->  Gmail / Send Email
```

- El POST se hace con `urllib.request` de la librería estándar: sin dependencias.
- La URL del webhook vive en `config/notificaciones.json`, que **no se versiona**.
- Solo severidad 9 (crítica) dispara correo. Con los datos de prueba son 2 correos.
- Asunto con prefijo `[DATOS DE PRUEBA - EstudIA]` para que nadie lo confunda
  con un incidente real.
- Deduplicación en `salidas/.enviadas.json` para no reenviar en cada corrida.

## Antes del pitch

Exportar el workflow desde n8n (**⋯ → Download**) y guardarlo aquí como
`flujo_alertas.json`, **sin credenciales**. Así queda versionado y se puede mostrar
aunque la instancia no esté disponible.

**Graba un video de 20 s del correo llegando.** Si falla el WiFi del salón, se
muestra el video y el pitch sigue.

## Licencia

n8n autohospedado (Community Edition) está bajo *Sustainable Use License*: gratuito
para uso interno. n8n Cloud es de pago con prueba gratuita.
