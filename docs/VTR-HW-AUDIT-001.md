# VTR-HW-AUDIT-001 — Auditoría de afirmaciones de hardware

> **Origen:** pregunta directa de Luis tras el hallazgo del riesgo de
> PSRAM/heap-corruption en `docs/VTR-FIRMWARE-001.md` ("¿qué otros
> aspectos de especificaciones de hardware no deberíamos asumir?") —
> esa pregunta motivó una revisión sistemática de todas las
> afirmaciones sobre hardware físico en el repositorio, no solo las del
> documento donde se encontró el primer caso.
> **Método:** cada afirmación se verificó contra fuente primaria
> (datasheet del fabricante, documentación oficial del driver/kernel) o
> se marca explícitamente como sin verificación posible a distancia.
> **Alcance:** este documento NO es exhaustivo de todas las
> afirmaciones técnicas del proyecto — se concentra en afirmaciones
> sobre **hardware físico específico** (RPi 4, Heltec V3/ESP32-S3,
> SX1262), porque ese es el patrón de riesgo que el caso de PSRAM ya
> demostró: una cifra o capacidad que suena razonable, viene de una
> fuente real, y aun así no aplica al modelo exacto del proyecto.

---

## 1. Hallazgo corregido — sensibilidad de receptor LoRa sin fuente citada

**Dónde:** `docs/VTR-SURVEY-001.md` §0, cálculo de link budget teórico.

**Qué se afirmaba:** "sensibilidad de referencia de datasheet ≈ −129
dBm para SF9/BW125" — sin indicar de qué datasheet, ni el razonamiento
detrás del número.

**Verificación realizada:** se recalculó la sensibilidad desde primeros
principios:

```
noise_floor(BW, NF) = -174 dBm/Hz + NF(dB) + 10·log10(BW en Hz)
sensibilidad(SF)    = noise_floor + SNR_requerido(SF)
```

Con `NF = 6 dB` (noise figure típico de un receptor LoRa real, no un
receptor ideal) y `BW = 125 kHz`: `noise_floor ≈ −117 dBm`. Con
`SNR_requerido(SF9) ≈ −12.5 dB` (progresión estándar LoRa, ~2.5 dB por
nivel de SF, consistente con la sensibilidad de −137 dBm a SF12 que
Semtech garantiza para el SX1262): `sensibilidad(SF9) ≈ −129.5 dBm`.

**Resultado:** el número original (`−129 dBm`) **era correcto**, pero
no estaba citado de forma verificable — coincidía por buen criterio
técnico al momento de escribirlo, no por estar anclado a una fuente
comprobable. La primera vez que intenté reproducir el cálculo desde
cero (sin noise figure, asumiendo receptor ideal) obtuve `−135.5 dBm` —
una discrepancia de 6.5 dB, que habría cambiado el alcance teórico
final de ~584 km a ~1239 km si se hubiera usado sin cuestionar. La
diferencia completa se explica por el noise figure del receptor real,
que la primera versión del documento no mencionaba como parte del
cálculo.

**Corrección aplicada:** `docs/VTR-SURVEY-001.md` ahora incluye el
cálculo completo con sus términos (noise floor, noise figure, SNR
requerido por SF), no solo el número final. El resultado final pasó de
"~580 km" a "~584 km" (diferencia menor, dentro del margen de
redondeo) — el número casi no cambió, pero ahora es verificable por
cualquiera que quiera reproducirlo, no solo citado de memoria.

**Discrepancia adicional encontrada y resuelta durante esta misma
verificación:** distintas fuentes citan `−137 dBm` y `−148 dBm` ambas
como "sensibilidad SX1262 a SF12/BW125" — una diferencia de 11 dB que
parece contradictoria a primera vista. Resuelto: `−137 dBm` es la
especificación **garantizada por Semtech** en el datasheet oficial del
chip (la cifra conservadora, correcta para cálculos de ingeniería);
`−148 dBm` es una cifra de marketing comparativo ("hasta") que aparece
en material promocional del Heltec V4 frente al chip SX1276 más viejo,
no una especificación garantizada del SX1262 mismo. Usar `−148 dBm`
para cualquier cálculo de ingeniería real habría sido optimista de
forma injustificada — la progresión de sensibilidad por SF usada en
este documento parte correctamente de `−137 dBm` (SF12 garantizado),
no de `−148 dBm`.

---

## 2. Hallazgo pendiente — tiempos de Argon2id "en RPi 4" nunca medidos

**Dónde:** `docs/DECISIONS-v0.5.0.md`, Decisión 2 (Opciones 2A/2B/2C).

**Qué se afirma:** "~80-100 ms en RPi 4" (profile `embedded`),
"150-200 ms" (profile `desktop`), "300-500 ms en RPi 4" (profile
`hardened`) — presentados sin calificador de "estimado" junto a otros
datos que sí son hechos verificados (ej. "Funciona en Heltec V3").

**Por qué esto es una discrepancia real, no solo falta de evidencia:**
el propio `docs/DOD-v0.5.0.md` confirma en otra sección que el único
número de timing realmente medido es **275 ms, en un entorno de 1
núcleo — no en RPi 4 real** (la propuesta #5 corrigió `lanes` de 4→1
tras esa medición). Ese número no coincide limpiamente con el rango
"150-200 ms en RPi 4" que `DECISIONS-v0.5.0.md` atribuye al mismo
profile (`desktop`, que es la opción 2B finalmente elegida) — y nadie
ha reconciliado ambos documentos todavía.

**No se corrige aquí porque requiere la medición pendiente, no una
búsqueda:** a diferencia del hallazgo #1 (que se resolvió con
verificación bibliográfica), este requiere ejecutar
`crypto_layer/argon2_derive.py` en hardware RPi 4 real — exactamente el
ítem ya pendiente en `docs/DOD-v0.5.0.md` §5 ("Validar presupuesto de
tiempo de Argon2id... en hardware RPi 4 real con 4 núcleos").

**Acción recomendada cuando se haga esa medición:** comparar el
resultado real contra los tres rangos de `DECISIONS-v0.5.0.md` (80-100,
150-200, 300-500 ms) explícitamente. Si el número medido no cae dentro
del rango atribuido a su profile, corregir `DECISIONS-v0.5.0.md` en esa
sesión — no solo añadir el dato nuevo sin reconciliar el viejo, que es
precisamente cómo se acumuló esta discrepancia.

---

## 3. Hallazgo pendiente — calidad de entropía del TRNG del RPi 4 sin validación estadística

**Dónde:** `docs/VTR-PKI-001.md` §3.3, paso 1 ("idealmente usando el RNG
de hardware — BCM2711 TRNG en RPi, ESP32-S3 TRNG en Heltec").

**Qué se verificó:** el RPi 4 (BCM2711) **sí tiene** un generador de
números aleatorios por hardware real, distinto del de generaciones
anteriores — confirmado en el árbol de dispositivos oficial del kernel
de Raspberry Pi: `compatible = "brcm,bcm2711-rng200"` (el sufijo
`-rng200` es un diseño de hardware distinto del `bcm2835-rng`/
`bcm2708-rng` de RPi 1/2/3, no solo un nombre distinto para el mismo
circuito). Existe la herramienta estándar (`rngtest`, parte del paquete
`rng-tools`) para correr los tests estadísticos FIPS 140-2 (Monobit,
Poker, Runs, Long Run, Continuous Run) contra cualquier fuente de
`/dev/hwrng`.

**Qué NO se pudo verificar a distancia:** no encontré ningún reporte
público específico de `rngtest` corrido contra el RNG200 del BCM2711
— los ejemplos de salida de `rngtest` con estadísticas FIPS 140-2 que sí
existen en fuentes públicas corresponden a las generaciones anteriores
del chip (`bcm2708-rng`/`bcm2835-rng`), no al RNG200 específico del RPi
4. Esto no significa que el RNG200 sea de mala calidad — significa que
**no hay evidencia pública fácilmente verificable de que sea de buena
calidad para el caso de uso específico de este proyecto** (generar
material criptográfico de llaves de dispositivo, según
`docs/VTR-PKI-001.md` §3.3).

**Acción recomendada, ejecutable en el bench sin esperar hardware
adicional:**

```bash
# En el RPi 4 real, antes de generar cualquier llave de dispositivo real:
sudo apt-get install rng-tools
cat /dev/hwrng | rngtest -c 1000
```

Si `rngtest` reporta múltiples fallas de FIPS 140-2 (no solo 1-2 de
1000, que es estadísticamente esperado incluso en una fuente sana — ver
ejemplo de `bcm2708-rng` en fuentes públicas, que reportó "FIPS 140-2
failures: 0" en una corrida de 100064 bits), eso sería una señal de
alerta real que ningún documento actual del proyecto puede anticipar
sin esa prueba — la calidad de un TRNG físico no se puede verificar
leyendo documentación, solo midiéndola contra el chip real.

**Nota de alcance:** esto NO bloquea el uso del TRNG mientras tanto —
el RNG del kernel Linux ya mezcla múltiples fuentes de entropía
(interrupciones, timing, y el TRNG hardware cuando está disponible), así
que `/dev/urandom`/`getrandom()` siguen siendo criptográficamente
seguros incluso si el TRNG hardware específico tuviera baja calidad,
según el diseño documentado del RNG de Linux moderno. El riesgo real es
más sutil: depender *explícitamente* del TRNG hardware como fuente
dedicada (en vez del RNG del kernel ya mezclado) sin haberlo validado,
que es lo que el paso 1 de `VTR-PKI-001.md` §3.3 sugiere como
"idealmente".

---

## 4. Patrón general identificado — para aplicar en futuras especificaciones de hardware

Los tres hallazgos comparten una estructura común que vale la pena
nombrar explícitamente, para reconocerla más rápido la próxima vez:

1. **Una cifra o capacidad de hardware se cita sin indicar la fuente
   exacta** (qué datasheet, qué sección, qué condiciones de medición) —
   el lector no puede verificar de dónde viene sin investigar desde
   cero.
2. **La cifra puede ser correcta por buen criterio técnico, y aun así
   no estar verificada** — el caso de la sensibilidad LoRa (#1) muestra
   que "estaba bien" y "estaba verificado" son cosas distintas; solo
   después de esta auditoría lo primero se volvió también lo segundo.
3. **Variantes del mismo chip/modelo tienen especificaciones distintas**
   — el caso de PSRAM (Heltec V3 vs. V4) y el caso del RNG200 (BCM2711
   vs. generaciones anteriores de Broadcom) muestran que el nombre de
   familia ("ESP32-S3", "Raspberry Pi", "BCM2835/2711") no garantiza que
   una característica de un miembro de la familia aplique a otro.
4. **La verificación real, cuando es posible, es barata** — confirmar
   el modelo exacto contra el datasheet del fabricante (PSRAM), correr
   `rngtest` en el hardware real (TRNG), o recalcular desde primeros
   principios con las fuentes correctas (sensibilidad LoRa) tomó minutos,
   no días. El costo de no hacerlo — un documento de referencia con un
   número equivocado que alguien usa para una decisión real más
   adelante — es desproporcionadamente mayor.

**Regla práctica adoptada a partir de esta auditoría:** toda cifra o
capacidad de hardware citada en documentación de VTR Continuity debe
indicar explícitamente su fuente (datasheet + sección, o "medición
propia pendiente de hardware real") — nunca "valor típico" o
"referencia de datasheet" sin precisar cuál.
