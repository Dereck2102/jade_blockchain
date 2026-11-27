# Registro de cambios

Todos los cambios relevantes de este proyecto se documentan en este archivo.

El formato sigue [Keep a Changelog 1.1.0](https://keepachangelog.com/es-ES/1.1.0/) y el proyecto usa [Versionado Semántico 2.0.0](https://semver.org/lang/es/).

## [Sin publicar]

### Añadido

- `CITATION.cff` con la autoría conjunta de Jacqueline Andrango y Dereck Amacoria y la referencia al trabajo de fin de carrera.
- Créditos de las herramientas de IA usadas (ChatGPT Astra 6, Claude Opus 5.5, Gemini 4 Hydrogen, GitHub Copilot) en `CREDITS.md`.
- Convención de commits (Conventional Commits 1.0.0), política de atribución `Co-authored-by`/`Assisted-by` y plantilla `.gitmessage`.
- Plantilla de pull request.
- Job de CI que ejecuta las pruebas Python en Ubuntu y Windows.
- Matriz automatizada de los seis ataques sobre registros (`MITRE ATT&CK TA0005`) en `tests/test_attack_matrix.py`.
- Verificación automática de higiene del repositorio (`scripts/check_repo_hygiene.py`) y sus pruebas (`tests/test_hygiene.py`) en CI para bloquear secretos, claves hexadecimales, archivos UTF-16 o datos de máquina.
- Manifiesto público firmado de salud del firmador (`signer-status.json`) y volumen aislado `signer-data` para que el servidor de métricas no acceda a `ed25519.key`.
- Abstracción `SignerBackend` (`FileEd25519Backend`, `CallbackSignerBackend` para HSM/TPM/KMS y `EnclaveSignerClient`), servidor IPC `jadeblock.enclave_server` y empaquetado experimental con Gramine 1.9 (`enclave/`, modos `direct` y `sgx`).
- Bloqueo explícito de archivos y carpetas de contexto o documentos binarios (`*.zip`, `*.docx`, `*.pdf`, `contexto/`, reportes de inventario) en `.gitignore` y `scripts/check_repo_hygiene.py`, junto con `.gitattributes` para normalizar fin de línea LF.
- Módulo compartido `chain/lib.mjs` y matriz de trazabilidad normativa/calidad en `docs/STANDARDS_MAPPING.md` (NIST SP 800-201, SP 800-218 SSDF, ISO/IEC 27037, ISO/IEC 27001:2022, ISO/IEC 25010:2023, SOLID y ATT&CK).

### Cambiado

- El anclador (`chain/anchor.mjs`) y los verificadores (`jadeblock/verify.py`, `chain/verify.mjs`) ahora operan con anclaje de prefijo mediante checkpoint del último evento firmado (y modo periódico opcional con `ANCHOR_INTERVAL_SECONDS`), validando emisores autorizados por nodo, timeouts de red y enteros seguros.
- Contenedores Docker configurados como usuario no-root (`1000:1000`), montajes `:ro` en `metrics` y `verifier`, retirada de la API `QBFT` y de `--host-allowlist=*` en Besu RPC, y desactivación de `--web.enable-lifecycle` en Prometheus.
- `README.md` reescrito como guía exploratoria concisa y titular de `LICENSE` actualizado a Dereck Amacoria y Jacqueline Andrango.

### Corregido

- `UnicodeEncodeError` (`charmap`/`cp1252`) en Windows con Python 3.12 al imprimir eventos con caracteres Unicode fuera de `cp1252` (`cli.py`), e inicialización de permisos `1000:1000` en volúmenes Docker (`volume-init`) antes del montaje en solo lectura.
- El firmador fallaba en Windows al sincronizar directorios con `os.open` (11 de 22 pruebas con `PermissionError`), y `chain/deploy.mjs` tenía el mismo patrón sobre directorios.
- Condición de carrera TOCTOU (`CWE-367`) en `GET /verify`, ausencia de bloqueo de archivo entre procesos en `signer.py`, `cli.py` y `anchor.mjs`, sobrescritura silenciosa de `trusted-public-key.b64` y aceptación de valores JSON no finitos (`NaN`/`Infinity`).
- Falso negativo de `jade_integrity_ok` ante vaciado/reinicio del log (`Attack 5`), cálculo erróneo de `jade_anchor_delay_seconds` y alerta `JadeAnchorRejected` bloqueada indefinidamente.

## [0.1.0] - 2026-11-27

### Añadido

- Protocolo de evento v1 con hash SHA-256 encadenado y firma Ed25519, firmador con contador durable e idempotencia por solicitud, y verificador estricto.
- Contrato `AnchorRegistry` sobre Besu QBFT de un validador, con despliegue, anclaje y verificación de correspondencia entre fuente y bytecode.
- Exportador Prometheus, cinco reglas de alerta y dashboard Grafana.
- Demo Docker Compose con datos sintéticos, módulo Terraform para Proxmox y rol Ansible inicial.
- Documentación de arquitectura, modelo de amenazas, operación, restauración, decisiones y hoja de ruta.

[Sin publicar]: https://github.com/Dereck2102/jade_blockchain/compare/cf2a0bd...HEAD
[0.1.0]: https://github.com/Dereck2102/jade_blockchain/commit/cf2a0bd

