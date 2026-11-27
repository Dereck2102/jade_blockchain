# Hoja de ruta y estado

## Implementado en el repositorio

- Evento v1 y vector determinista Unicode/campos opcionales.
- Ledger JSONL, firma Ed25519, contador persistente y retry idempotente.
- Verificador estricto con resultados JSON, exit codes diferenciados y cobertura por checkpoint de prefijo.
- Demo Compose con Besu QBFT de un validador, contrato Solidity, compilación y anclador del último evento (con modo periódico opcional `ANCHOR_INTERVAL_SECONDS`).
- Matriz automatizada de seis ataques sobre registros (`MITRE ATT&CK TA0005`).
- Verificación automática de higiene del repositorio (secretos y datos locales) en CI.
- Métricas locales, reglas Prometheus y dashboard de ejemplo por nodo.
- Módulo inicial de creación LXC y rol Ansible para Debian/systemd.

## Validado localmente en esta revisión

- 38 pruebas Python: vectores Unicode, JSON estricto RFC 8259, matriz de 6 ataques (`MITRE ATT&CK TA0005`), concurrencia/poda del firmador, manifiesto aislado de salud, métricas ante vaciado de log, endpoints HTTP y escáner de higiene.
- Test y compilación Solidity; `npm audit` informó cero vulnerabilidades.
- `docker compose config --quiet`, `promtool check config` (cinco reglas) y parseo del dashboard Grafana.
- Recorrido Docker real local: Besu QBFT inició, el contrato se desplegó, una solicitud repetida generó el mismo único evento, el anclador publicó el contador 1 y el verificador devolvió `verified`, con integridad, autenticidad y cobertura completas.
- Terraform `fmt -check`, `init -backend=false` y `validate` con Terraform 1.17.2; `ansible-playbook --syntax-check`.
- El workflow público está definido para ejecutar estas comprobaciones sin secretos. Su ejecución remota todavía no ha finalizado; no se reporta como CI completada.

No se ejecutó `terraform apply`; no se accedió a Proxmox ni al laboratorio.

## Pendiente

- Captura real de cambios de archivos del anfitrión y eventos Docker; instalación como inspector systemd.
- Autenticación/traslado seguro de eventos entre nodos, rotación y revocación de claves, política de recuperación completa y sellado independiente del tiempo.
- Réplica QBFT con varios validadores administrativamente independientes, failover y pruebas de consenso.
- Proxmox real: prueba de plantilla, permisos, red aprobada, actualizaciones, backup y restauración.
- Trazabilidad de operación extendida, hardening del RPC/telemetría, retención y alertas/notificaciones conectadas.
- Revisión independiente de seguridad y de supuestos de evidencia.

La ruta no promete certificación forense, resultados científicos, garantías judiciales ni protección hardware.
