#!/bin/sh
set -eu

MODE="${JADE_ENCLAVE_MODE:-direct}"

case "$MODE" in
  direct)
    echo "[jade-enclave] Iniciando en modo Gramine direct (sin aislamiento hardware SGX)." >&2
    exec gramine-direct /app/enclave/python3
    ;;
  sgx)
    if [ ! -c /dev/sgx_enclave ]; then
      echo "[jade-enclave] ERROR: Se solicitó JADE_ENCLAVE_MODE=sgx pero /dev/sgx_enclave no está disponible. No se degrada silenciosamente a modo direct." >&2
      exit 1
    fi
    if [ ! -f /app/enclave/python3.manifest.sgx ] || [ ! -f /app/enclave/python3.sig ]; then
      echo "[jade-enclave] ERROR: Faltan artefactos firmados de SGX (python3.manifest.sgx / python3.sig)." >&2
      exit 1
    fi
    echo "[jade-enclave] Iniciando dentro de enclave hardware Intel SGX." >&2
    exec gramine-sgx /app/enclave/python3
    ;;
  *)
    echo "[jade-enclave] ERROR: JADE_ENCLAVE_MODE inválido: '$MODE' (use 'direct' o 'sgx')." >&2
    exit 1
    ;;
esac
