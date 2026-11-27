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
- Verificación automática de higiene del repositorio (`scripts/check_repo_hygiene.py`) en CI para bloquear secretos o datos de máquina.

### Cambiado

- El anclador (`chain/anchor.mjs`) y los verificadores (`jadeblock/verify.py`, `chain/verify.mjs`) ahora operan con anclaje de prefijo mediante checkpoint del último evento firmado (y modo periódico opcional con `ANCHOR_INTERVAL_SECONDS`), rechazando prefijos rotos, duplicados y regresiones.
- `README.md` reescrito como guía exploratoria concisa.
- Titular de `LICENSE` actualizado a Dereck Amacoria y Jacqueline Andrango.

### Corregido

- El firmador fallaba en Windows al sincronizar directorios con `os.open` (11 de 22 pruebas con `PermissionError`).

## [0.1.0] - 2026-11-27

### Añadido

- Protocolo de evento v1 con hash SHA-256 encadenado y firma Ed25519, firmador con contador durable e idempotencia por solicitud, y verificador estricto.
- Contrato `AnchorRegistry` sobre Besu QBFT de un validador, con despliegue, anclaje y verificación de correspondencia entre fuente y bytecode.
- Exportador Prometheus, cinco reglas de alerta y dashboard Grafana.
- Demo Docker Compose con datos sintéticos, módulo Terraform para Proxmox y rol Ansible inicial.
- Documentación de arquitectura, modelo de amenazas, operación, restauración, decisiones y hoja de ruta.

[Sin publicar]: https://github.com/Dereck2102/jade_blockchain/compare/cf2a0bd...HEAD
[0.1.0]: https://github.com/Dereck2102/jade_blockchain/commit/cf2a0bd

