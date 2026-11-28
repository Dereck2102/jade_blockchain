# Backup y restauración

La clave Ed25519, `signer-state.json` y el registro de solicitudes son un conjunto: restaurar solo el ledger o solo la clave puede romper autenticidad, contadores o idempotencia. Incluye también los datos del nodo Besu/genesis, contrato desplegado y `anchors.json` para conservar identidad y cobertura. Una restauración parcial se debe tratar como nueva identidad/red y documentar explícitamente.

## Backup

1. Detén el stack con `docker compose down` (sin `--volumes`) para obtener una copia coherente.
2. Usa un directorio de backup fuera de Git y exporta cada volumen persistente (si `.env` cambia los nombres, sustitúyelos aquí; añade también los volúmenes Prometheus/Grafana si habilitaste observabilidad):

   ```sh
   mkdir -p "$HOME/jade-backups"
   for volume in jade-blockchain-chain-network jade-blockchain-besu-data jade-blockchain-events jade-blockchain-signer; do
     docker run --rm -v "$volume:/source:ro" -v "$HOME/jade-backups:/backup" \
       busybox:1.37.0 sh -c 'tar -czf "/backup/$1.tar.gz" -C /source .' sh "$volume"
   done
   sha256sum "$HOME"/jade-backups/*.tar.gz
   ```

   Para los servicios opcionales, incluye `jade-blockchain-prometheus-data` y `jade-blockchain-grafana-data` en la lista.

3. Mantén fuera del repositorio backups, volúmenes exportados y toda clave. Protege el archivo de claves y el backup de forma equivalente.
4. Registra hash del archivo, fecha y versión del software en el procedimiento operativo propio. No se incluye telemetría ni archivo de backup en Git.

## Restauración

1. Detén Compose y conserva una copia del estado actual antes de restaurar.
2. Configura `.env` con nombres nuevos de destino (`JADE_CHAIN_VOLUME=jade-restore-chain`, `JADE_BESU_VOLUME=jade-restore-besu`, `JADE_EVENTS_VOLUME=jade-restore-events`, `JADE_SIGNER_VOLUME=jade-restore-signer`). Esto conserva los volúmenes originales sin sobrescribirlos.
3. Crea y carga los volúmenes desde el mismo conjunto consistente:

   ```sh
   docker volume create jade-restore-chain
   docker volume create jade-restore-besu
   docker volume create jade-restore-events
   docker volume create jade-restore-signer
   for pair in "jade-restore-chain:jade-blockchain-chain-network" \
               "jade-restore-besu:jade-blockchain-besu-data" \
               "jade-restore-events:jade-blockchain-events" \
               "jade-restore-signer:jade-blockchain-signer"; do
     target=${pair%%:*}
     archive=${pair#*:}
     docker run --rm -v "$target:/target" -v "$HOME/jade-backups:/backup:ro" \
       busybox:1.37.0 sh -c 'tar -xzf "/backup/$1.tar.gz" -C /target' sh "$archive"
   done
   ```

4. Inicia `docker compose up -d besu contract metrics`, verifica bytecode, chain ID, identidades y salud; luego ejecuta generador/anclador/verificador con un ID de prueba nuevo.
5. Si faltan clave, contador o base Besu, no generes una clave sustituta para continuar una identidad anterior. Recupera el conjunto completo o crea un entorno nuevo con identidad nueva y registra que no hereda anclas/identidad.

La restauración no ha sido probada contra un Proxmox real. No destruyas el backup fuente hasta validar la copia restaurada y su verificación local.
