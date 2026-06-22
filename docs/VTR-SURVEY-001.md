# VTR-SURVEY-001 — Site Survey RF: protocolo de medición

> **Estado:** propuesta documentada, lista para ejecución.
> **Prioridad:** máxima — bloquea la validación real de Tier 0 del
> checklist post-#10 (ver `docs/DOD-v0.5.0.md` §5 y jerarquización del
> 20-jun-2026).
> **Ejecución planeada:** lunes (próxima sesión activa). Hardware ya
> disponible: 2× Heltec WiFi LoRa 32 V3.
> **Esta sesión:** documentación únicamente, sin ejecución de campo —
> domingo es break del proyecto, ningún paso de este documento requiere
> trabajo de campo antes del lunes.

---

## 0. Por qué este survey es indispensable, no opcional

`config/rf_config.yaml` ya fija los parámetros de la Capa 1 LoRa:

```yaml
rf:
  lora:
    frequency_mhz: 915
    tx_power_dbm: 14
    spreading_factor: 9
    bandwidth_khz: 125
    duty_cycle_percent: 1.0
```

Con esos parámetros, el link budget teórico del SX1262 (sensibilidad de
referencia de datasheet ≈ −129 dBm para SF9/BW125, antenas Heltec
estándar ~2 dBi) da un alcance en espacio libre de **~580 km** (modelo
Friis, línea de vista ideal, sin obstáculos). Ese número no significa
nada para el despliegue real — es el techo teórico, no una promesa. En
un entorno industrial/portuario real (estructuras metálicas, tanques de
almacenamiento, grúas, naves de proceso), el alcance real puede ser una
fracción pequeña de eso, y la única forma de saber cuánto es medir.

**El propósito de este survey es cerrar la brecha entre ese número
teórico y el comportamiento real del corredor Tampico-Altamira-Madero.**
Sin esta medición, el Fallback Tier 2 RF descrito en
`docs/ROADMAP-v0.5.0.md` y todo el trabajo ya cerrado en
`crypto_layer/vtrc_bundle.py` y `core/storage_guardian.py` sigue siendo
correcto en el papel pero no validado en el terreno donde realmente
tiene que operar.

---

## 1. Objetivo de la medición

Confirmar, en al menos 2 ubicaciones reales del tipo que VTR Continuity
está diseñado para cubrir (petroquímica, CFE, manufactura, logística
portuaria — ver memoria del proyecto), tres métricas por cada enlace
punto a punto:

1. **RSSI** (Received Signal Strength Indicator) — potencia de la señal
   recibida, en dBm.
2. **SNR** (Signal-to-Noise Ratio) — relación señal/ruido, en dB. Crítico
   en entorno industrial porque el ruido RF de motores, variadores de
   frecuencia, y equipo eléctrico pesado puede ser alto incluso con buen
   RSSI.
3. **PER** (Packet Error Rate) — porcentaje de paquetes perdidos o
   corruptos sobre el total enviado, a una distancia y configuración
   fijas.

El resultado de estas tres métricas, en cada ubicación y a cada
distancia probada, es lo que reemplaza la cifra teórica de 580 km por el
alcance real operativo — y decide si los parámetros actuales de
`rf_config.yaml` sirven tal cual, o si necesitan ajuste antes de
considerarse parte de un release.

---

## 2. Qué se mide exactamente — protocolo paso a paso

### 2.1 Configuración de los dos nodos

Ambos Heltec deben transmitir con **exactamente** los parámetros ya
fijados en `rf_config.yaml` — el survey valida esos parámetros
específicos, no una configuración genérica de LoRa:

| Parámetro | Valor a usar | Por qué este valor |
|---|---|---|
| Frecuencia | 915 MHz | ISM, sin licencia — Ruta A del proyecto |
| Potencia TX | 14 dBm | Ya fijado en `rf_config.yaml` |
| Spreading Factor | SF9 | Ya fijado — balance alcance/velocidad |
| Ancho de banda | 125 kHz | Ya fijado |
| Duty cycle | ≤1% | Cumplimiento ISM — no transmitir más del 1% del tiempo |

Un nodo actúa como **transmisor fijo** (TX) en un punto de referencia
(ej. la ubicación donde se instalaría el equipo de planta/proxy DMZ). El
otro actúa como **receptor móvil** (RX), desplazándose a las distancias
de prueba.

### 2.2 Distancias de prueba

Para cada ubicación, medir en al menos estas distancias (ajustar según
el tamaño real del sitio, pero mantener el patrón de progresión):

- 50 m (línea de vista directa, si es posible)
- 150 m
- 300 m
- 500 m (o el límite del perímetro del sitio, lo que sea menor)

En cada distancia, anotar también si hay **obstrucción directa** entre
TX y RX (ej. un tanque, una nave, equipo industrial) — esto es tan
importante como la distancia numérica, porque en el corredor
Tampico-Altamira-Madero la obstrucción metálica es la variable que más
diferencia va a hacer frente al modelo de espacio libre.

### 2.3 Qué transmitir — payload realista, no solo paquetes de prueba

No basta con enviar paquetes vacíos. El payload de prueba debe aproximar
el tamaño real que `EncryptedBundle` (Capa 1, `core/crypto_transport.py`)
produce en operación — un frame de bundle `.vtrc` fragmentado por
`BundleFragmenter` (Capa 2, `core/dtn_fragmenter.py`) ya documentado en
el proyecto como de 222 bytes por fragmento. Usar ese tamaño de payload
en las pruebas, no el payload mínimo de ejemplo que trae el firmware de
fábrica del Heltec.

### 2.4 Procedimiento de medición por distancia

En cada distancia y ubicación:

1. Enviar un lote de **100 paquetes** desde TX hacia RX, con el payload
   de 222 bytes del punto 2.3, respetando el duty cycle de 1%.
2. En el RX, registrar por cada paquete recibido: RSSI y SNR (el
   firmware del Heltec/SX1262 expone ambos valores por paquete recibido
   vía el registro del chip — no requiere instrumentación adicional).
3. Contar cuántos de los 100 paquetes enviados se recibieron
   correctamente (CRC válido) — el resto, sea por no llegar o llegar
   corrupto, cuenta como error para el cálculo de PER.
4. **PER = (100 − paquetes_recibidos_validos) / 100 × 100%**
5. Repetir el lote de 100 paquetes una segunda vez en la misma posición
   exacta, para confirmar que el primer resultado no fue un evento
   aislado (interferencia momentánea de un equipo industrial cercano,
   por ejemplo) — si los dos lotes difieren en más de 10 puntos
   porcentuales de PER, repetir una tercera vez y registrar las tres
   mediciones, no promediar silenciosamente la discrepancia.

### 2.5 Qué anotar en cada punto de medición

Por cada combinación de ubicación + distancia, registrar como mínimo:

- Ubicación (nombre del sitio, no solo coordenadas)
- Distancia real medida (no la nominal planeada — la real, con cinta
  métrica/GPS si la distancia nominal no es exacta en campo)
- RSSI promedio y rango (mínimo–máximo) de los paquetes recibidos
- SNR promedio y rango
- PER de cada uno de los lotes de 100 (mínimo 2 lotes por punto)
- Obstrucción directa: sí/no, y qué tipo (tanque metálico, nave de
  proceso, vegetación, etc.)
- Hora del día y condición climática (la humedad y lluvia afectan la
  propagación a 915 MHz de forma medible, vale la pena registrarlo)
- Fuentes de ruido RF visibles en el entorno inmediato (motores,
  variadores de frecuencia, soldadura activa, radios de planta en la
  misma banda — aunque la banda ISM 915 es distinta de canales de radio
  industrial, vale la pena anotar qué hay alrededor)

---

## 3. Ubicaciones candidatas

Esta propuesta no fija las ubicaciones exactas — eso depende de acceso
real y autorización de sitio, que es decisión y gestión propia. Pero el
criterio de selección, según el alcance documentado del proyecto
(memoria: petroquímica, CFE, manufactura, logística portuaria, corredor
Tampico-Altamira-Madero), debería cubrir al menos:

1. **Una ubicación con obstrucción metálica densa** — representativa de
   una planta petroquímica o instalación CFE (tanques, estructuras de
   proceso). Esta es la condición más adversa y la más relevante para el
   caso de uso real del proyecto.
2. **Una ubicación más abierta** — representativa de logística portuaria
   o exteriores de manufactura, para tener un punto de comparación menos
   adverso y poder aislar cuánto del PER/RSSI degradado en el punto 1 es
   atribuible específicamente a la obstrucción metálica.

Si solo es posible medir en una ubicación esta primera vez, priorizar la
de obstrucción metálica densa — es la condición donde el sistema
realmente necesita funcionar, y la que más se aleja del modelo teórico
de espacio libre.

---

## 4. Criterios de interpretación — qué hacer con los números

Esta sección importa tanto como la medición misma: un PER de 15% no dice
nada por sí solo sin un criterio de qué es aceptable para el caso de
uso.

- **PER ≤ 5%** en una distancia/ubicación: parámetros actuales de
  `rf_config.yaml` confirmados como suficientes para esa condición, sin
  cambios.
- **PER entre 5% y 20%**: zona de degradación tolerable solo si el
  protocolo de Capa 2 (`BundleFragmenter`, retransmisión DTN) puede
  compensarla — anotar como "requiere validar con reintentos reales",
  no descartar ni aceptar todavía.
- **PER > 20%**: la configuración actual no es viable en esa
  ubicación/distancia tal cual. Las palancas de ajuste a considerar, en
  este orden de prioridad (menor a mayor costo de cambio):
  1. Reducir distancia operativa esperada en ese tipo de sitio (ajuste
     de expectativa, no de config).
  2. Subir el Spreading Factor (SF9 → SF10/SF11): mejora alcance y
     resistencia a ruido, a costa de tiempo de aire por paquete —
     impacto directo en el presupuesto de duty cycle del 1%, hay que
     recalcular cuántos bundles caben por hora si se sube el SF.
  3. Evaluar antena externa de mayor ganancia en vez de la antena
     incluida del Heltec — cambio de hardware, no solo de config.
  4. Solo como último recurso, subir `tx_power_dbm` — el Heltec V3 ya
     está configurado a 14 dBm, que es razonablemente alto para uso
     continuo; subir más acerca al límite regulatorio ISM y acorta vida
     de batería en nodos no alimentados por línea.

- **RSSI** y **SNR** se interpretan juntos, no por separado: un RSSI
  aceptable con SNR muy bajo (ruido alto) puede seguir produciendo PER
  alto — es la combinación, no un solo número, la que predice
  confiabilidad real del enlace.

---

## 5. Qué hacer con los resultados — siguiente paso después del survey

Los resultados de esta medición alimentan directamente:

- **`docs/DOD-v0.5.0.md` §5** — el ítem "Site survey RF en ≥2 ubicaciones
  industriales/portuarias reales" se cierra con evidencia real (no
  teórica) por primera vez en el proyecto.
- **Posible actualización de `config/rf_config.yaml`** — si el survey
  revela que SF9/125kHz/14dBm no es suficiente para el peor caso medido,
  esos valores se ajustan con evidencia real respaldándolos, siguiendo el
  mismo criterio que ya se aplicó en la propuesta #5 (corrección de
  `lanes=4` a `lanes=1` tras medición real, no por intuición).
  Cualquier cambio a `rf_config.yaml` debe documentarse con el mismo
  nivel de evidencia que esa corrección — antes/después, número medido,
  no solo "se ajustó".
- **Referencia futura `VTR-RD-005`** mencionada en el comentario del
  YAML actual (`frequency_mhz: 915 # ISM, Ruta A — ver VTR-RD-005`): ese
  documento no existe todavía en el repositorio. Los resultados de este
  survey son el contenido natural de ese documento — al cerrarse el
  survey, conviene generar `docs/VTR-RD-005.md` con los datos reales
  medidos, reemplazando la referencia pendiente por un documento real.

---

## 6. Checklist de campo — qué llevar el lunes

- [ ] 2× Heltec WiFi LoRa 32 V3 (ya disponibles), cargados o con fuente
  de energía confirmada para toda la sesión de medición.
- [ ] Cable USB-C de respaldo para cada Heltec (alimentación/datos de
  emergencia si la batería se agota a media sesión).
- [ ] Medio de registro de datos en campo — hoja de cálculo simple o
  libreta, con las columnas de la sección 2.5 ya preparadas de antemano
  para no improvisar el formato en sitio.
- [ ] Medio de medir distancia real (GPS del teléfono es suficiente;
  cinta métrica si las distancias son cortas y hay obstrucciones que
  compliquen la línea de vista del GPS).
- [ ] Confirmación de acceso/autorización a la(s) ubicación(es)
  elegida(s) — gestionado antes del lunes, no el día mismo.
- [ ] Este documento (`docs/VTR-SURVEY-001.md`) impreso o accesible
  offline en sitio — el protocolo de medición no depende de
  conectividad, que es justamente el punto del proyecto.

---

## 7. Qué NO cubre este survey — alcance explícito

Para que no haya ambigüedad sobre qué se está validando y qué no:

- No valida BLE Mesh (Capa corto alcance) — solo LoRa 915 MHz.
- No valida el comportamiento de `GhostScheduler` (patrones de tráfico
  fantasma) en condiciones reales de jamming activo — eso es una prueba
  distinta, de seguridad/RF adversarial, no de alcance.
- No valida el sneakernet `.vtrc` — ese fallback es explícitamente para
  cuando LoRa falla, no depende de su alcance.
- No sustituye el fuzzing UART + LoRa simulado (`VTR-FUZ-001`,
  pendiente del checklist) — ese es un test de robustez de protocolo, no
  de propagación RF.

Este survey responde una sola pregunta con evidencia real: **¿a qué
distancia, con qué grado de error, funciona LoRa con los parámetros
actuales, en el tipo de sitio donde VTR Continuity debe operar?** Todo
lo demás queda fuera de su alcance deliberadamente.
