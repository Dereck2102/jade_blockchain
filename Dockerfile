FROM python:3.12.12-slim
WORKDIR /app
COPY pyproject.toml ./
COPY jadeblock ./jadeblock
RUN python -m pip install --no-cache-dir .
ENTRYPOINT ["python3", "-m", "jadeblock.cli"]
