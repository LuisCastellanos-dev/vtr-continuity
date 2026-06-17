# VTR-PKI-001 — Esquema PKI Dos Niveles y Procedimientos de Custodia

> **Documento:** VTR-PKI-001
> **Versión:** v1.0
> **Fecha:** 2026-06-16
> **Estado:** APROBADO — depende de VTR-CRYPTO-001 (no lo contradice)
> **Alcance:** VTR Continuity v0.5.0 — Épica B (Infraestructura PKI)
> **Decisión base:** 4C — CA dos niveles, root offline + intermediate online
> (ver `docs/DECISIONS-v0.5.0.md`)

---

## 0. Relación con VTR-CRYPTO-001

Este documento no introduce primitivas nuevas fuera de las ya fijadas, salvo
una: el esquema de Shamir's Secret Sharing (SSS) para la custodia distribuida
de la CA root, decidido en esta sesión para no diferir M-of-N a v0.6 como
contemplaba el roadmap original. Esa decisión se documenta y justifica en la
sección 4 de este documento, incluyendo el riesgo real que tiene SSS mal
implementado y por qué el diseño aquí descrito lo mitiga.

**Recordatorio de estado pendiente (VTR-CRYPTO-002):** el `device_secret` de
32 bytes y su partición read-only firmada por CA siguen siendo diseño
pendiente, no implementado. Este documento describe cómo la CA *firmaría*
ese mecanismo una vez exista — no asume que ya existe.

---

## 1. Jerarquía de la PKI

```
VTR-Root-CA (Ed25519, offline)
  └── VTR-Provisioning-Intermediate (Ed25519, online en bench)
         ├── device-001.vtr.local
         ├── device-002.vtr.local
         └── ...
```

| Nivel | Algoritmo | Validez | Custodia |
|---|---|---|---|
| Root | Ed25519 | 10 años | Offline, USB cifrado LUKS, fragmentado vía SSS 3-de-5 (ver §4) |
| Intermediate | Ed25519 | 2 años | Online, bench Tampico air-gapped salvo durante operación de firma |
| Device cert | Ed25519 | 18 meses (alineado con rotación de `device_secret`, ver §5) | Embebido en partición firmada del dispositivo |

**Por qué Ed25519 en los tres niveles, no RSA:** consistencia con la primitiva
ya fijada para firma de bundles `.vtrc` en VTR-CRYPTO-001 — evita mezclar
familias criptográficas distintas en una misma cadena de confianza, y produce
firmas y llaves significativamente más pequeñas que RSA-3072 a nivel de
seguridad equivalente, lo cual importa cuando un certificado de dispositivo
eventualmente viaja dentro de un bundle `.vtrc` de tamaño limitado por el
enlace LoRa.

---

## 2. Librería para generación y firma de certificados — justificación verificada

Se evaluó si usar el CLI de OpenSSL directamente (invocado desde scripts) o la
librería Python `cryptography` (pyca) ya fijada en VTR-CRYPTO-001 para
Argon2id/HKDF.

**Hallazgo verificado:** OpenSSL soporta generación de llaves Ed25519, firma y
verificación mediante PureEdDSA según RFC 8032, con formatos de llave
compatibles con RFC 8410. Para algoritmos de firma sin digest configurable
como Ed25519, cualquier parámetro de digest pasado a `openssl ca` es ignorado
— comportamiento esperado del estándar, no una limitación. Existe un reporte
histórico (2018) de un bug al crear certificados X.509 CA con llaves Ed25519
en versiones antiguas de OpenSSL; no es un bloqueo vigente en OpenSSL 3.x.

**Decisión:** se usa `cryptography` (pyca) ≥45.0 — la misma versión mínima ya
fijada en VTR-CRYPTO-001 — para todo el ciclo de vida de la CA (generación de
llaves, construcción y firma de certificados X.509, generación de CRL). Razón:
`cryptography` expone bindings maduros sobre OpenSSL específicamente para
construir estructuras X.509 en Python, evitando invocar el binario `openssl`
vía subprocess desde scripts de provisioning — eliminando una superficie de
ataque innecesaria (shell injection si los parámetros no se sanitizan
perfectamente, y dependencia de la versión de OpenSSL del sistema en vez de un
pin de librería controlado por VTR).

Esta decisión no contradice el uso de PyNaCl para Ed25519 en la firma de
bundles `.vtrc` (VTR-CRYPTO-001 §1): son responsabilidades distintas — PyNaCl
firma mensajes/bundles directamente, `cryptography` construye y firma
*estructuras X.509* (certificados, CRL) que internamente usan Ed25519. No se
mezclan ambas para la misma operación.

```python
# Ejemplo: generación de la llave root con cryptography (pyca >=45.0)
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from cryptography import x509
from cryptography.x509.oid import NameOID
import datetime

root_key = Ed25519PrivateKey.generate()

subject = issuer = x509.Name([
    x509.NameAttribute(NameOID.COMMON_NAME, "VTR-Root-CA"),
    x509.NameAttribute(NameOID.ORGANIZATION_NAME, "Vector Telemetry Research"),
])

root_cert = (
    x509.CertificateBuilder()
    .subject_name(subject)
    .issuer_name(issuer)
    .public_key(root_key.public_key())
    .serial_number(x509.random_serial_number())
    .not_valid_before(datetime.datetime.utcnow())
    .not_valid_after(datetime.datetime.utcnow() + datetime.timedelta(days=3650))  # 10 años
    .add_extension(x509.BasicConstraints(ca=True, path_length=1), critical=True)
    .sign(root_key, algorithm=None)  # Ed25519 no usa digest — None es correcto aquí
)
```

---

## 3. Procedimiento de creación — Root y Intermediate

### 3.1 Creación de la Root (ceremonia única, offline)

1. Ejecutar en máquina **air-gapped** del bench de Tampico — sin red, Wi-Fi y
   Bluetooth deshabilitados por hardware, no solo por software.
2. Generar `root_key` con `Ed25519PrivateKey.generate()`.
3. Construir y autofirmar el certificado root con validez de 10 años,
   `BasicConstraints(ca=True, path_length=1)` — el `path_length=1` limita
   explícitamente la cadena a un único nivel intermedio, sin sub-CAs
   adicionales no contempladas.
4. **Inmediatamente después de firmar el primer batch de certificados
   intermedios** (ver 3.2), la llave privada root se fragmenta vía SSS 3-de-5
   (sección 4) y el material original en texto plano se destruye de forma
   segura (sobreescritura múltiple del USB temporal usado durante la
   ceremonia).
5. Registro de la ceremonia: fecha, hardware usado, hash SHA-256 del
   certificado root resultante, testigos presentes — almacenado en
   `device_registry.vtrdb` (cifrado, ver Épica C).

### 3.2 Creación de la Intermediate (operación periódica, ~1-2 veces/año)

1. Generar `intermediate_key` en el bench (puede estar online para esta
   operación específica, pero idealmente con red desconectada durante la
   generación de la llave).
2. Construir el certificado intermediate con validez de 2 años,
   `BasicConstraints(ca=True, path_length=0)` — sin permitir sub-CAs propias.
3. Firmar con la llave root (que en este punto solo existe reconstruida
   temporalmente a partir de 3 de las 5 partes SSS — ver §4.3).
4. Tras la firma, la llave root reconstruida se destruye de memoria de forma
   explícita (no depender del garbage collector; sobreescribir el buffer
   antes de liberar la referencia).
5. La llave intermediate queda operativa en el bench, protegida por el
   cifrado de disco del propio bench (LUKS), para firmar certificados de
   dispositivo en operación diaria.

### 3.3 Emisión de certificado de dispositivo (operación diaria, por cada Heltec/RPi)

1. El dispositivo genera su propio par de llaves Ed25519 en el bench
   (idealmente usando el RNG de hardware — BCM2711 TRNG en RPi, ESP32-S3 TRNG
   en Heltec, ya documentado en el historial del proyecto).
2. Se construye un CSR (Certificate Signing Request) o estructura equivalente
   con la llave pública del dispositivo y su identificador lógico
   (`device-NNN.vtr.local`).
3. La Intermediate firma el certificado de dispositivo, validez 18 meses.
4. El certificado resultante se almacena en la partición firmada del
   dispositivo — la misma partición pendiente de diseño en VTR-CRYPTO-002.

---

## 4. Custodia de la CA Root — Shamir's Secret Sharing 3-de-5

### 4.1 Por qué SSS, y por qué no se adoptó sin verificar el riesgo primero

La decisión original del roadmap diferían M-of-N a v0.6 (`B6`, prioridad P2).
En esta sesión se decidió adelantarlo a v0.5.0, pero **no sin antes verificar
el historial real de fallas de SSS en producción**, porque el esquema tiene
antecedentes documentados de implementaciones rotas con consecuencias graves:

- Trail of Bits encontró bugs reales de aritmética modular en la
  implementación de SSS usada por el esquema de firma de umbral de Binance
  (`tss-lib`) y la mayoría de sus forks activos, permitiendo a un atacante
  robar llaves secretas de otros participantes.
- Un caso documentado en la función "Fragmented Backups" de la wallet Armory
  usó hashing repetido en vez de un generador de números aleatorios para
  derivar los coeficientes del polinomio. Ese determinismo, combinado con
  otros errores, rompió el esquema completamente: un atacante con la primera
  parte y cualquier otra parte adicional podía recuperar el secreto, sin
  importar qué umbral se hubiera configurado.
- Una empresa de custodia de Bitcoin, tras investigación extensa, rechazó
  usar SSS para sus clientes precisamente por estos riesgos, recomendando
  multisig en su lugar.
- Las librerías Python sin auditoría disponibles (`sss`, `tno.mpc.encryption_
  schemes.shamir`) declaran explícitamente que su criptografía no ha sido
  revisada ni auditada.

**Conclusión de la verificación:** el esquema matemático de Shamir es sólido;
las implementaciones rotas fallan en la generación de aleatoriedad o en la
falta de validación de integridad de las partes, no en la teoría. Por eso el
diseño de esta sección añade explícitamente las dos capas que el caso Armory
demuestra que son indispensables.

### 4.2 Librería elegida

**PyCryptodome**, módulo `Crypto.Protocol.SecretSharing`. Es la única opción
entre las evaluadas con respaldo de trayectoria real (implementa el esquema
del paper original de Shamir, "How to share a secret") y sin la advertencia
explícita de ausencia de auditoría que cargan las alternativas puramente
Python (`sss`, `tno.mpc`). No es la librería ya fijada en VTR-CRYPTO-001 para
otras primitivas — se documenta como excepción justificada, no como
inconsistencia accidental.

```
# requirements.txt — añadir junto a pynacl y cryptography
pycryptodome>=3.20  # módulo Crypto.Protocol.SecretSharing para custodia CA root
```

### 4.3 Las 4 capas de validación — mitigación explícita del vector de Armory

**Capa 1 — Verificación del RNG antes de confiar en la generación.**
Antes de usar `Shamir.split()` en producción, se ejecuta un test que genera
el mismo secreto dos veces de forma independiente y confirma que las 5 partes
resultantes son diferentes en cada corrida. Partes idénticas en corridas
distintas serían la señal exacta del fallo que rompió Armory (coeficientes
deterministas en vez de aleatorios).

```python
def test_sss_uses_real_randomness():
    """Si esto falla, NO se debe usar Shamir.split() en producción."""
    secret = b"\x00" * 16  # secreto de prueba, 16 bytes (tamaño requerido por PyCryptodome)
    shares_run1 = Shamir.split(3, 5, secret)
    shares_run2 = Shamir.split(3, 5, secret)
    assert shares_run1 != shares_run2, (
        "CRÍTICO: el split produjo las mismas partes en corridas distintas. "
        "Esto indica generación determinista de coeficientes — el mismo "
        "patrón de fallo que rompió las Fragmented Backups de Armory."
    )
```

**Capa 2 — HMAC de integridad sobre el secreto completo.**
PyCryptodome documenta explícitamente que la reconstrucción puede tener éxito
y aun así producir el secreto incorrecto si alguna parte presentada está
corrupta o proviene de un participante malicioso. VTR nunca confía en que
"si combinó, es correcto":

```python
import hmac, hashlib

def generate_root_shares(root_key_bytes: bytes) -> tuple[list, bytes]:
    """Fragmenta la llave root y produce un HMAC de verificación.

    El HMAC se calcula sobre el secreto ORIGINAL antes de fragmentar,
    usando una clave derivada y públicamente conocida del esquema VTR
    (no es secreta — su único propósito es detectar reconstrucción
    incorrecta, no aportar confidencialidad).
    """
    verification_key = b"VTR-PKI-001-SSS-INTEGRITY-CHECK-V1"  # constante de dominio
    expected_hmac = hmac.new(verification_key, root_key_bytes, hashlib.sha256).digest()
    shares = Shamir.split(3, 5, root_key_bytes)
    return shares, expected_hmac

def reconstruct_root_key(shares: list, expected_hmac: bytes) -> bytes:
    if len(shares) < 3:
        raise InsufficientSharesError(
            f"Se requieren al menos 3 partes, se recibieron {len(shares)}"
        )
    reconstructed = Shamir.combine(shares[:3])
    verification_key = b"VTR-PKI-001-SSS-INTEGRITY-CHECK-V1"
    actual_hmac = hmac.new(verification_key, reconstructed, hashlib.sha256).digest()
    if not hmac.compare_digest(actual_hmac, expected_hmac):
        raise SSSIntegrityError(
            "La llave reconstruida no coincide con el HMAC esperado. "
            "Una o más partes están corruptas o son ilegítimas. "
            "NO USAR esta llave reconstruida para firmar nada."
        )
    return reconstructed
```

**Capa 3 — Umbral estricto, sin reconstrucción parcial.**
El esquema es fijo: **3-de-5**. El código rechaza explícitamente cualquier
intento con menos de 3 partes (`InsufficientSharesError` arriba) — nunca se
intenta "adivinar" con menos partes de las requeridas.

**Capa 4 — Custodia distribuida, sin concentración geográfica.**

| Parte | Custodio | Ubicación | Estado |
|---|---|---|---|
| 1 | Luis (operador principal) | USB cifrado, caja fuerte Tampico (junto al bench) | Definido |
| 2 | Luis (copia personal) | USB cifrado, ubicación secundaria de confianza | **Pendiente — a definir por Luis** |
| 3 | Persona de confianza designada por VTR | Custodia independiente | **Pendiente — a designar por Luis** |
| 4 | Backup digital cifrado | Medio físico fuera de Tampico (ej. caja de seguridad bancaria) | **Pendiente — a definir por Luis** |
| 5 | Reserva de emergencia | Sellada, apertura solo en escenario de recuperación documentado | **Pendiente — a definir por Luis** |

> **Nota explícita:** este documento no inventa ubicaciones ni custodios
> específicos para las partes 2, 3, 4 y 5. Son decisiones operativas que
> dependen de circunstancias personales y de confianza de Luis Castellanos,
> no de un criterio técnico que este documento pueda resolver por sí mismo.
> El roadmap (Épica B, tarea B4) queda abierto hasta que se confirmen.

### 4.4 Escenario de recuperación — pérdida total del bench de Tampico

Si el bench se pierde por completo (incendio, robo, desastre natural) **antes**
de que existan registros redundantes adicionales:

1. La parte 1 (en la misma caja fuerte que el bench) se considera perdida
   junto con el bench.
2. Se requiere recuperar al menos 2 de las partes 2, 3, 4 o 5 — todas ellas
   geográficamente separadas del bench por diseño — más cualquier parte
   adicional disponible, hasta completar 3.
3. La reconstrucción se realiza en un bench de reemplazo, siguiendo el mismo
   protocolo air-gapped de la sección 3.1, con el HMAC de la sección 4.3 como
   verificación obligatoria antes de confiar en la llave reconstruida.
4. Tras la reconstrucción exitosa, se genera un **nuevo conjunto de 5 partes**
   inmediatamente (no se reutilizan las partes antiguas) y se procede a
   re-certificar la Intermediate.

Esto alinea la práctica de VTR con los principios de NIST SP 800-57 (gestión
de ciclo de vida de llaves criptográficas, incluyendo recuperación ante
pérdida) e ISO/IEC 27037 (preservación de cadena de custodia para evidencia
digital, aplicado aquí a material criptográfico crítico) — el marco
solicitado explícitamente para este escenario, en vez de una política
improvisada.

---

## 5. Revocación y período de validez

| Certificado | Validez | Mecanismo de revocación |
|---|---|---|
| Root | 10 años | N/A — revocar la root implica re-emitir toda la flota; evento catastrófico, no operación rutinaria |
| Intermediate | 2 años | Si se compromete, la Root (reconstruida vía SSS) la revoca y firma una nueva, sin invalidar certificados de dispositivo ya emitidos por la intermediate anterior si esta no fue la causa del compromiso |
| Device cert | 18 meses, alineado con rotación de `device_secret` | CRL distribuida vía bundle `.vtrc` — ver §5.1 |

### 5.1 CRL en entorno air-gapped

No hay conectividad permanente para OCSP. La distribución de CRL ocurre como
parte del propio canal de bundles `.vtrc`:

1. El bench genera una CRL firmada por la Intermediate cada vez que se revoca
   un dispositivo.
2. La CRL se empaqueta como un bundle `.vtrc` especial (tipo `crl-update`) y
   se distribuye por los mismos canales que cualquier otro bundle — LoRa,
   BLE Mesh, o Sneakernet.
3. Cada nodo mantiene una copia local de la última CRL recibida con su
   timestamp; al verificar la firma de un bundle entrante, el nodo consulta
   primero contra su copia local de CRL.
4. **Limitación reconocida:** un nodo aislado por mucho tiempo (jamming
   prolongado, ver VTR-SEC-001 S#2) puede operar con una CRL desactualizada.
   Esto es un riesgo aceptado del modelo air-gapped — se documenta, no se
   resuelve con una solución que requeriría conectividad permanente
   (contradiría el propósito mismo de VTR Continuity).

---

## 6. Pendientes que este documento NO resuelve

- Custodios y ubicaciones específicas de las partes SSS 2, 3, 4 y 5 (sección
  4.3) — decisión operativa de Luis, no técnica.
- Procedimiento detallado paso a paso de la ceremonia de firma con comandos
  exactos para el bench físico de Tampico (queda para el SOP de provisioning,
  Épica C / E11).
- Mecanismo de detección de que un nodo remoto necesita una CRL actualizada
  de forma proactiva (hoy es pasivo — el nodo solo actualiza cuando recibe un
  bundle `crl-update`). Posible mejora futura, no bloqueante para v0.5.0.
