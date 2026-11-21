# Contexto para Claude Code

Proyecto del equipo **E-8ZNU «security»** para el reto de Kenworth de la Montaña
(EstudIA, Capa 2, Ciberseguridad básico). Monitoreo de eventos, clasificación de
alertas y plan de hardening.

El contexto completo y la historia de decisiones están en
`Kenworth_Recursos_de_Prueba/CONTEXTO_PROYECTO.md`. **Ese archivo NO está en el
repositorio** (está en `.gitignore`): contiene información real de la empresa y
del equipo, y este repositorio es público. Existe solo en la máquina de cada
integrante y se comparte por un canal privado.

Este archivo resume lo que hay que tener presente al escribir código.

## Reglas duras

1. **No modificar `Kenworth_Recursos_de_Prueba/`.** Es el paquete entregado por el
   curso. Es la única fuente de datos de entrada y la base de comparación para
   validar. Se lee, nunca se escribe.
2. **Trabajo 100 % offline.** El código solo lee archivos locales. No escanea, no
   hace peticiones a ninguna IP del escenario, no modifica configuraciones. Las IP
   `10.60.x.x`, `192.0.2.x`, `198.51.100.x` y `203.0.113.x` son etiquetas
   documentales, no destinos.
   La única salida a internet permitida es el POST opcional al webhook de n8n,
   detrás de una bandera y hacia una cuenta propia del equipo.
3. **Python 3.9.** La Mac del equipo tiene únicamente el Python del sistema
   (3.9.6), sin Homebrew. No usar `match`, ni `X | Y` en anotaciones evaluadas, ni
   nada posterior a 3.9. **Sin dependencias externas:** solo librería estándar.
4. **No hay Node.** El tablero es HTML, CSS y JavaScript plano, sin build. No
   introducir npm, Vite, React ni Next.js sin instalar Node primero.
5. **Lenguaje de las señales.** Separar siempre *evento* (una observación),
   *alerta* (resultado de una regla) e *incidente* (lo confirmado por revisión
   humana). Nunca afirmar que hubo intrusión o extracción de datos. Nunca inferir
   CVE a partir de «actualizaciones pendientes». «No registrado» es ausencia de
   evidencia.
6. **Nunca versionar la URL del webhook** ni credenciales. `config/notificaciones.json`
   está en `.gitignore`; solo se versiona `config/notificaciones.ejemplo.json`.
7. **El repositorio es PÚBLICO.** Nada de lo que está en el documento de
   contexto local puede copiarse a un archivo versionado: ni personas de contacto
   de la empresa, ni su infraestructura o productos de seguridad reales, ni su
   historial de incidentes, ni los datos del laboratorio del equipo (direcciones,
   usuarios, credenciales). En el repositorio solo va lo que se deriva de los
   datos de prueba. Antes de cada commit que agregue documentación, revisar que no
   se haya filtrado nada de eso.

## Arquitectura

```
Kenworth_Recursos_de_Prueba/  (CSV + JSON de entrada, intacto)
            |
   analizador/analizador.py   (reglas + severidad)
            |
     web/alertas.json         <-- EL CONTRATO
       |          |
  web/ (Vercel)   n8n (webhook) --> correo
```

`web/alertas.json` es el contrato entre las tres piezas. Si cambia su forma, hay
que actualizar el tablero. Contiene: `generado_en`, `origen_datos`, `parametros`,
`resumen`, `alertas[]` y `eventos[]` (los 324 eventos crudos, para que el tablero
muestre la evidencia de cada alerta en un clic).

El analizador se ejecuta **en local** y el JSON resultante se commitea. No corre en
Vercel. Ventaja adicional: el historial de git de `web/alertas.json` es trazabilidad
real de cómo cambiaron las alertas en cada corrida.

## Validación obligatoria

Tras **cualquier** cambio en la lógica de detección, confirmar que las 4 reglas
originales siguen reproduciendo la referencia del curso:

```bash
python3 analizador/analizador.py
diff salidas/alertas.csv Kenworth_Recursos_de_Prueba/07_Validacion/Referencia_alertas.csv
```

Debe salir sin diferencias. Las reglas nuevas se agregan **una por una**,
revalidando en cada paso. Si una regla nueva cambia el resultado de las 4
originales, está mal implementada.

Además hay 4 casos controlados en `Kenworth_Recursos_de_Prueba/07_Validacion/Casos_controlados.json`:
4 fallos (0 alertas), 5 fallos (1), 5 fallos dispersos fuera de ventana (0) y
frontera de 10 minutos inclusive (1).

## Severidad acordada

`severidad = criticidad_activo × peso_señal`, ambos en escala 1–3, igual que la
escala impacto × exposición que pide la rúbrica del curso.

Criticidad: Alta = 3, Media = 2, Baja = 1 (de `02_Datos/inventario_activos.csv`).

| Señal | Peso |
|---|---|
| Fallos repetidos **seguidos de éxito** | 3 |
| Volumen alto a destino externo **+ regla inconsistente** | 3 |
| Denegaciones repetidas desde Internet a activo crítico | 2 |
| Uso de R02 (excepción que no registra) | 2 |
| Fuera de horario | 1 |

Corte: **9 = crítica** (dispara correo), 6 = alta, 3–4 = media, 1–2 = baja.
**Supresión por CH01:** si el evento cae dentro de la ventana autorizada
(`02_Datos/cambios_autorizados.csv`) y no excede su límite, baja a informativa.
CH01 cubre BACKUP-LAB el 2026-11-20 de 02:00 a 02:30 desde 10.60.0.20, y
**no autoriza envío externo de datos**.

## Reglas pendientes de implementar

Están listadas como TODO numerado en `analizador/analizador.py`. En orden:
enriquecer con inventario, reconocer CH01, correlacionar «fallos seguidos de
éxito», detectar denegaciones repetidas desde Internet, alertar por uso de R02 y
calcular severidad.

Dato útil: los 12 eventos `deny` de `203.0.113.77` hacia DB-LAB (E0309–E0320) **no
los detecta** el analizador original. Es la mejora más visible del MVP.

## Estilo

- Código y comentarios **en español**, que es el idioma del equipo y del entregable.
- El equipo es **principiante en ciberseguridad y en programación**: preferir
  código explícito y legible sobre código corto o ingenioso. Cada regla con un
  comentario que explique qué busca y por qué.
- Nombres de archivos y carpetas nuevos en minúsculas y sin acentos.
