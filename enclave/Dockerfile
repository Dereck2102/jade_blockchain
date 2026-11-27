# Imagen experimental del servicio firmador con Gramine 1.9 (Ubuntu 24.04).
# Soporta JADE_ENCLAVE_MODE=direct (cualquier CPU x86_64) y JADE_ENCLAVE_MODE=sgx
# (requiere servidor con Intel SGX + FLC y mapeo de /dev/sgx_enclave).
FROM gramineproject/gramine:1.9-noble

ARG SIGNER_FS_TYPE=chroot
ARG REMOTE_ATTESTATION=none

RUN apt-get update && apt-get install -y --no-install-recommends \
    python3 \
    python3-pip \
    python3-cryptography \
    && rm -rf /var/lib/apt/lists/* \
    && groupadd -g 1000 jade \
    && useradd -u 1000 -g 1000 -m -s /usr/sbin/nologin jade \
    && mkdir -p /app/enclave /signer \
    && chmod 0700 /signer

WORKDIR /app
COPY pyproject.toml ./
COPY jadeblock ./jadeblock
RUN pip3 install --break-system-packages --no-deps --no-cache-dir .

COPY enclave/jade-signer.manifest.template /app/enclave/python3.manifest.template
COPY enclave/entrypoint.sh /app/enclave/entrypoint.sh

RUN ARCH_LIBDIR="/lib/$(gcc -dumpmachine)" \
    && gramine-manifest \
      -Dlog_level=error \
      -Darch_libdir="$ARCH_LIBDIR" \
      -Dentrypoint="$(command -v python3)" \
      -Dsigner_fs_type="$SIGNER_FS_TYPE" \
      -Dremote_attestation="$REMOTE_ATTESTATION" \
      /app/enclave/python3.manifest.template \
      /app/enclave/python3.manifest \
    && chmod 0755 /app/enclave/entrypoint.sh \
    && chown -R 1000:1000 /app /signer

# Nota: para modo SGX real, firme el enclave con su clave de operador fuera de la imagen pública:
#   gramine-sgx-sign --key <clave_enclave.pem> --manifest /app/enclave/python3.manifest --output /app/enclave/python3.manifest.sgx
USER 1000:1000
ENV JADE_ENCLAVE_MODE=direct \
    JADE_SIGNER_DIR=/signer \
    JADE_SIGNER_HOST=0.0.0.0 \
    JADE_SIGNER_PORT=9201
EXPOSE 9201
ENTRYPOINT ["/app/enclave/entrypoint.sh"]
