# Decisiones de diseño

## D-001 — Compatibilidad de hash v1

Se conserva exactamente la serialización de referencia Python (`sort_keys=True`, `ensure_ascii=False`, separadores predeterminados), excluyendo `hash`, `firma`, `firma_n` y `firma_error`. No se compacta ni se transforma a JSON canónico distinto. El vector Unicode determinista fija la compatibilidad; los cambios incompatibles requieren otra versión.

## D-002 — Firmador software

Ed25519 usa `cryptography`; clave, contador y respuestas idempotentes permanecen en almacenamiento local durable. El contador y las solicitudes procesadas se respaldan junto con la clave. Esta versión no implementa HSM, SGX o atestación remota.

## D-003 — Verificación previa al anclaje

Solidity no verifica Ed25519. El anclador valida hash, cadena y firma antes de enviar la transacción; contrato controla el emisor y el contador por nodo. Esta confianza fuera de cadena se documenta y no se presenta como verificación criptográfica ejecutada por la EVM.

## D-004 — Demo de un validador

QBFT local de un validador reduce dependencias para probar el recorrido. Se trata de una red de desarrollo centralizada, con identidades generadas de nuevo por volúmenes; no sirve como evidencia de descentralización ni disponibilidad.

## D-005 — Separación de responsabilidades

Terraform crea recursos nuevos; Ansible configura Debian y systemd; Compose gestiona servicios de demo. No se usan provisioners Terraform para configurar máquinas, ni despliegue automático de CI, importación o destrucción de infraestructura existente.
