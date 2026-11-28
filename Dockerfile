FROM python:3.15.1-slim
WORKDIR /app
RUN groupadd -g 1000 jade \
    && useradd -u 1000 -g 1000 -m -s /usr/sbin/nologin jade \
    && mkdir -p /data/signer \
    && chmod 0755 /data \
    && chmod 0700 /data/signer \
    && chown -R 1000:1000 /app /data
COPY pyproject.toml ./
COPY jadeblock ./jadeblock
RUN python -m pip install --no-cache-dir .
USER 1000:1000
ENTRYPOINT ["python3", "-m", "jadeblock.cli"]
