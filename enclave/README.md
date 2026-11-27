# Firmador aislado y soporte TEE / HSM (experimental)

Este directorio proporciona el empaquetado opcional con **Gramine 1.9** para ejecutar el microservicio firmador (`python3 -m jadeblock.enclave_server`) separado del generador/inspector.

> **Estado real:** la interfaz `SignerBackend` y el protocolo IPC (`jadeblock/backends.py`, `jadeblock/enclave_server.py`) están probados en la suite unitaria Python. La imagen Gramine y el modo hardware `sgx` son **experimentales** y no se ejecutan en los runners públicos de GitHub Actions (que carecen de `/dev/sgx_enclave`).

## Opciones de aislamiento disponibles

1. **Software local (por defecto):** `EventSigner` con `FileEd25519Backend` y volumen aislado `signer-data`.
2. **HSM / PKCS#11 / Cloud KMS / TPM 2.0 en proceso:** inyectando `CallbackSignerBackend(public_key, sign_fn)` en `EventSigner(state_dir, backend=...)` para que la clave privada no resida en texto claro en el sistema de archivos.
3. **Gramine `direct` (sin hardware SGX):** ejecuta el firmador bajo LibOS Gramine por socket TCP (`127.0.0.1:9201`), útil para validar el manifiesto antes de desplegar en hardware compatible:
   ```sh
   docker compose --profile enclave up -d enclave-signer
   docker compose --profile synthetic run --rm demo generate \
     --signer-endpoint enclave-signer:9201 \
     --events /data/events.jsonl \
     --public-key /data/trusted-public-key.b64 \
     --node demo-node --request-id enc-001
   ```
4. **Gramine `sgx` (requiere hardware Intel SGX + FLC):**
   - Requiere procesador **Intel Xeon Scalable** con *Flexible Launch Control*, kernel Linux 5.11+ (`/dev/sgx_enclave`, `/dev/sgx_provision`), construir con `--build-arg SIGNER_FS_TYPE=encrypted` y firmar `python3.manifest.sgx` con una clave privada de operador fuera de la imagen pública.
   - Si se define `JADE_ENCLAVE_MODE=sgx` y `/dev/sgx_enclave` no existe, `entrypoint.sh` **falla cerrado** y no degrada silenciosamente a modo `direct`.
5. **Alternativas sin SGX (Intel TDX, AMD SEV-SNP, AWS Nitro Enclaves):**
   - `jadeblock.enclave_server` puede alojarse directamente dentro de una VM confidencial (TDX / SEV-SNP) o enclave Nitro sin modificar el protocolo de eventos ni el contrato `AnchorRegistry.sol`.
