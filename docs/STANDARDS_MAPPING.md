# Trazabilidad con marcos de ciberseguridad, calidad y diseño

> Autoevaluación técnica de referencia (actualizada el 2026-11-27). Este documento vincula los controles implementados en el repositorio con normas y marcos reconocidos, distinguiendo explícitamente qué está cubierto en código y qué permanece con brecha. **No constituye certificación, auditoría externa ni dictamen de conformidad formal.**

## 1. Marcos forenses, de seguridad y ciclo de vida (NIST / ISO)

| Marco y edición vigente | Control / práctica | Implementación y evidencia en el repositorio | Estado y brecha |
|---|---|---|---|
| **NIST SP 800-201** (*NIST Cloud Computing Forensic Reference Architecture*, jul. 2024, [CSRC](https://csrc.nist.gov/pubs/sp/800/201/final)) | Preparación forense previa al incidente y preservación fuera del origen | Cadena SHA-256 (`jadeblock/protocol.py`), firma Ed25519 con contador durable (`jadeblock/signer.py`) y anclaje de prefijo en Besu (`chain/anchor.mjs`). | **Evaluado con brecha:** la demo usa generador sintético; falta el inspector del anfitrión/Docker y almacenamiento externo Loki/Alloy. |
| **NIST SP 800-92** (*Guide to Computer Security Log Management*, sep. 2006, [CSRC](https://csrc.nist.gov/pubs/sp/800/92/final)) | Protección de integridad de registros frente a alteración, truncado o vaciado | Verificación separada de integridad, autenticidad y cobertura de anclaje (`jadeblock/verify.py`, `chain/verify.mjs`) probada contra 6 ataques en `tests/test_attack_matrix.py`. | **Parcial (alcance demo):** retención a largo plazo, rotación firmada y copia remota fuera del host quedan pendientes. |
| **NIST SP 800-218 v1.1 (SSDF)** (*Secure Software Development Framework*, feb. 2022, [CSRC](https://csrc.nist.gov/pubs/sp/800/218/final)) | `PW.1` / `PW.4` / `PW.7` / `PW.8`: privilegio mínimo, revisión estática, pruebas automatizadas y bloqueo de secretos | Contenedores no-root (`UID 1000`), volúmenes `:ro` y volumen `signer-data` aislado (`compose.yaml`), `npm audit`, matriz CI Ubuntu/Windows y `scripts/check_repo_hygiene.py`. | **Parcial:** faltan fijado de imágenes Docker por digest `@sha256:` y lockfile Python con hashes (`pip-audit`). |
| **ISO/IEC 27037:2012** (*Guidelines for identification, collection, acquisition and preservation of digital evidence*, [ISO](https://www.iso.org/standard/44381.html)) | Proceso auditable y repetible de preservación y verificación matemática | Esquema determinista v1 con vector Unicode (`tests/test_protocol.py`), verificación de fuente/bytecode del contrato (`chain/lib.mjs`) y códigos de salida distinguibles (`0`/`1`/`2`). | **Evaluado con brecha:** no sustituye cadena de custodia pericial ni validación de herramienta bajo ISO/IEC 27041. |
| **ISO/IEC 27001:2022** (Anexo A: `A.8.15` Registros, `A.8.16` Monitoreo, `A.8.24` Criptografía, [ISO](https://www.iso.org/standard/27001)) | Generación/protección de logs, alertas de anomalías y gestión de claves | Ed25519 + SHA-256, clave privada aislada del exportador mediante manifiesto firmado `signer-status.json`, protección contra sobrescritura de `trusted-public-key.b64` y 5 reglas en `observability/alerts.yml`. | **Evaluado con brecha:** sin HSM/Intel SGX real, un único validador QBFT y alertas sin canal externo (Alertmanager/SMTP). |

## 2. Calidad de producto (ISO/IEC 25010:2023) y principios SOLID

Referencia: **ISO/IEC 25010:2023** (*Systems and software engineering — SQuaRE — Product quality model*, nov. 2023, [ISO](https://www.iso.org/standard/78176.html)).

- **Seguridad (confidencialidad, integridad, autenticidad, no repudio técnico):**
  - Mitigación de **CWE-367 (TOCTOU)** en `/verify` leyendo los bytes de `events.jsonl` una sola vez (`evaluate_verification_snapshot` en `jadeblock/metrics.py`) y contrastando hash y conteo en `chain/lib.mjs`.
  - Mitigación de **CWE-306 / CWE-350** en Besu retirando la API `QBFT` de HTTP RPC y restringiendo `--host-allowlist` (`compose.yaml`).
  - Mitigación de **CWE-250 / CWE-732** aislando `ed25519.key` en el volumen `signer-data` y validando la salud del firmador con la clave pública sobre `signer-status.json` (inversión/desacoplamiento respecto de la clave privada).
- **Fiabilidad (tolerancia a fallos y recuperabilidad):**
  - Bloqueos exclusivos entre procesos (`file_lock` en Python y `withFileLock` en Node.js — **CWE-362**), escrituras atómicas con `fsync`, idempotencia por `request_id` con poda acotada (`prune_confirmed_requests`), y timeouts explícitos en `fetch`, JSON-RPC y servidor HTTP acotado (`BoundedHTTPServer` — **CWE-400**).
- **Compatibilidad e interoperabilidad:**
  - Serialización JSON estricta RFC 8259 (`allow_nan=False` y rechazo de `NaN`/`Infinity` en `jadeblock/protocol.py` — **CWE-436**) y validación de enteros seguros (`MAX_SAFE_INTEGER` — **CWE-681**) entre Python, Node.js y Solidity `uint64`.
- **Mantenibilidad (principios SOLID aplicados como heurística):**
  - *Responsabilidad única (SRP):* separación entre esquema/criptografía (`protocol.py`), persistencia/estado (`signer.py`), verificación pura dividida en cadena/firmas y cobertura de anclas (`verify.py`), interfaz CLI (`cli.py`) y exposición HTTP (`metrics.py`). En `chain/`, `lib.mjs` centraliza compilación `solc`, verificación on-chain y persistencia atómica antes duplicadas en 5 archivos.
  - *Segregación y mínimo acoplamiento (ISP / DIP):* el exportador de métricas ya no depende de instanciar `EventSigner` ni leer `ed25519.key` cuando dispone del manifiesto público firmado.
- **Portabilidad:**
  - Ejecución verificada en Windows y POSIX (`_fsync_directory`, `file_lock` con `msvcrt`/`fcntl` y matriz CI `ubuntu-latest` + `windows-latest`).

## 3. Cobertura frente a evasión de defensas (MITRE ATT&CK TA0005)

| Escenario (`tests/test_attack_matrix.py`) | Técnica ATT&CK | Capa que lo detecta | Métrica / estado resultante |
|---|---|---|---|
| Editar el contenido de un evento | `T1565.001` | Cadena SHA-256 (`integrity.ok = false`) | `status = invalid`, `jade_integrity_ok = 0` |
| Borrar un evento intermedio | `T1070` | Cadena SHA-256 + contador (`integrity.ok = false`) | `status = invalid`, `jade_integrity_ok = 0` |
| Borrar un evento y recalcular hashes | `T1070` | Firma Ed25519 (`authenticity.ok = false`) | `status = invalid`, `jade_integrity_ok = 0` |
| Falsificar contenido y recalcular hashes | `T1565.001` | Firma Ed25519 (`authenticity.ok = false`) | `status = invalid`, `jade_integrity_ok = 0` |
| Vaciar el log y reiniciar cadena desde `n=1` | `T1070.002` | Cobertura de anclas (`anchor_coverage.status = invalid`) | `status = invalid`, `jade_integrity_ok = 0` |
| Revertir o borrar el contador del firmador | `T1565` | Fallo cerrado del firmador + contrato `AnchorRegistry` + anclas | `RuntimeError` / `CounterNotIncreasing` / `jade_integrity_ok = 0` |
