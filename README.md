# JaDe Blockchain

Prototipo reproducible de inspección continua, firma de eventos e integridad de logs con anclaje en blockchain privada (**Hyperledger Besu QBFT**).

## ¿Por qué y qué problema resuelve?

En arquitecturas efímeras (funciones serverless y contenedores de corta duración), las instancias pueden desaparecer antes de recopilar sus registros, y un hash simple en disco puede recalcularse tras alterar un archivo. **JaDe Blockchain** combina tres capas para detectar manipulaciones y borrados:

1. **Cadena de hashes SHA-256** sobre registros JSONL (detecta edición o borrado).
2. **Firma Ed25519 con contador monotónico** e idempotencia por solicitud (detecta reconstrucción de la cadena sin la clave).
3. **Anclaje periódico del último evento** en un contrato Solidity sobre Besu QBFT (detecta vaciado del log y regresión del contador).

## ¿Cuándo usarlo (y cuándo no)?

- **Sí:** para pruebas de concepto, docencia, evaluación técnica de cadenas de custodia digitales y desarrollo del agente de captura.
- **No:** en producción institucional ni como evidencia judicial o pericial. Esta base usa eventos sintéticos, firma software sin aislamiento Intel SGX y una red QBFT de un único validador.

## ¿Con qué está construido?

| Capa | Tecnología |
|---|---|
| Núcleo y verificador | Python 3.12+ (`cryptography`), esquema de evento v1 |
| Contrato y anclaje | Solidity 0.8.39, Node.js (`ethers`, `solc`), Hyperledger Besu (QBFT) |
| Observabilidad | Exportador Prometheus, 5 reglas de alerta, dashboard Grafana |
| Orquestación e infra | Docker Compose, Terraform (`bpg/proxmox`), Ansible (Debian 12) |

## ¿Dónde está cada parte?

- [`jadeblock/`](jadeblock) — Protocolo v1, firmador durable, CLI, verificador y métricas.
- [`chain/`](chain) — Contrato `AnchorRegistry.sol`, compilación, despliegue, anclaje periódico y verificador on-chain.
- [`observability/`](observability) — Configuración de Prometheus, alertas y dashboard de Grafana.
- [`infrastructure/proxmox/`](infrastructure/proxmox) y [`ansible/`](ansible) — Base para crear y configurar 3 contenedores LXC en Proxmox.
- [`tests/`](tests) — Pruebas unitarias, sonda del firmador y matriz automatizada de 6 ataques (`MITRE ATT&CK TA0005`).
- [`docs/`](docs) — [Arquitectura](docs/ARCHITECTURE.md), [modelo de amenazas](docs/THREAT_MODEL.md), [operación](docs/OPERATIONS.md), [restauración](docs/RESTORE.md), [decisiones](docs/DECISIONS.md) y [hoja de ruta](docs/ROADMAP.md).

## ¿Cómo probarlo?

### Con Docker Compose (flujo completo)

Requisitos: Docker Engine con Compose v2.

```sh
cp .env.example .env
docker compose --profile synthetic build
docker compose up -d besu contract metrics
docker compose --profile synthetic run --rm demo generate \
  --events /data/events.jsonl --state-dir /data/signer \
  --public-key /data/trusted-public-key.b64 --node demo-node --request-id demo-001
docker compose --profile synthetic run --rm anchor
docker compose --profile synthetic run --rm verifier
```

Para activar Prometheus (`127.0.0.1:9090`) y Grafana (`127.0.0.1:3000`):

```sh
docker compose --profile observability up -d prometheus grafana
```

Detén con `docker compose down` (sin `--volumes` para conservar claves, cadena y eventos). Si configuras `ANCHOR_INTERVAL_SECONDS=15` en `anchor`, publica solo el último evento firmado de forma periódica.

### Solo núcleo Python (sin Docker)

```sh
python -m pip install .
python -m unittest discover -s tests -v
python -m jadeblock.cli generate --events data/events.jsonl \
  --state-dir data/signer --public-key data/trusted-public-key.b64 --request-id demo-001
python -m jadeblock.cli verify --events data/events.jsonl \
  --public-key data/trusted-public-key.b64 --anchors data/anchors.json
```

## Autoría y licencia

Creado originalmente por **Jacqueline Andrango** y **Dereck Amacoria** (TESA, Quito, 2026); mantenido por Dereck Amacoria. Consulta [CREDITS.md](CREDITS.md) (incluye atribución de herramientas de IA), [CITATION.cff](CITATION.cff), [CONTRIBUTING.md](CONTRIBUTING.md), [SECURITY.md](SECURITY.md) y [LICENSE](LICENSE) (MIT).
