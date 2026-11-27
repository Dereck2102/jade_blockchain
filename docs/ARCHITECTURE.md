# Arquitectura y alcance

## Antecedente observado, no reproducción

Una especificación previa describe tres LXC Debian 12 (monitor y dos nodos), inspectores/ancladores systemd, Grafana Alloy, firmador Ed25519 en Docker, Besu QBFT, Prometheus, Loki y Grafana. Esta entrega no dispone de código, servidor ni datos fuente de ese laboratorio. La descripción contextualiza el trabajo, pero no se afirma haber importado ni reproducido su implementación.

## Recorrido implementado para demo

1. `jadeblock.cli` genera un evento sintético con fecha, nodo, origen, tipo, nivel, `hash_anterior` y `datos`.
2. `EventSigner` persiste una clave Ed25519, contador y resultados por `request_id`. Archivos escritos se sustituyen atómicamente, con `fsync` del archivo y directorio.
3. El hash es SHA-256 del evento sin `hash`, `firma`, `firma_n` y `firma_error`, serializado como `json.dumps(evento, sort_keys=True, ensure_ascii=False).encode("utf-8")` con separadores predeterminados.
4. El mensaje de firma es UTF-8 de `n|hash`; la firma Ed25519 se representa en base64. El primer `hash_anterior` contiene 64 ceros.
5. El anclador comprueba secuencia, hash y firma fuera de cadena y publica hash de evento y hash de firma en el contrato.
6. El contrato solo permite al emisor autorizado representar su nodo y exige contador creciente. Mantiene contador, hashes y marca de tiempo por nodo.
7. El verificador local informa por separado integridad del ledger, autenticidad de las firmas y cobertura del prefijo de anclas, incluyendo eventos posteriores pendientes.

La versión de protocolo es v1 y se mantiene separada del cuerpo JSON para no alterar el hash de referencia. El contrato almacena hashes; no verifica firmas Ed25519 en Solidity. La verificación pre-transacción es software en el anclador y no equivale a una prueba en cadena.

## Identidades/consenso

La red local inicia un validador QBFT generado por Besu y una cuenta de despliegue aleatoria financiada en el genesis local. Las claves viven en volúmenes persistentes del host Docker. Un solo validador es centralizado, no tolera su pérdida y no demuestra descentralización, independencia administrativa ni disponibilidad.

## Infraestructura

Terraform crea tres contenedores LXC nuevos a partir de valores proporcionados. `prevent_destroy` bloquea su destrucción accidental por Terraform. Ansible instala/configura el sistema operativo y unidad systemd de métricas. Compose administra los servicios de la demo. Ninguna fase configura redes del hipervisor u OPNsense.

La inspección real de archivos y Docker del anfitrión, el transporte de eventos real y la réplica multi-nodo no están implementados. El indicador `jade_capture_healthy` permanece en cero en la demostración.
