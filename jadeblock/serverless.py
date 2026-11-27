"""Simulador determinista del ciclo de vida de funciones efímeras (serverless)."""

from datetime import datetime, timedelta, timezone
import uuid


def build_function_lifecycle_bodies(
    *,
    node: str,
    function_name: str,
    invocation_id: str | None = None,
    simulate_failure: bool = False,
    start_time: datetime | None = None,
) -> list[tuple[str, dict]]:
    """Genera la secuencia completa de eventos de una función efímera antes de destruirse.

    Devuelve pares ``(suffix, partial_body_without_hash_anterior)`` para encadenar
    y firmar en orden: creación, inicio, log de ejecución, finalización y destrucción.
    """
    if not isinstance(node, str) or not node.strip():
        raise ValueError("El nombre del nodo no puede estar vacío")
    if not isinstance(function_name, str) or not function_name.strip():
        raise ValueError("El nombre de la función no puede estar vacío")

    clean_fn = function_name.strip()
    inv_id = invocation_id or uuid.uuid4().hex[:8]
    container_name = f"fn-{clean_fn}-{inv_id}"
    t0 = start_time or datetime.now(timezone.utc)

    log_message = (
        f"ERROR fallo controlado en {clean_fn} (invocacion={inv_id})"
        if simulate_failure
        else f"OK ejecucion completada en {clean_fn} (invocacion={inv_id})"
    )
    exit_code = 1 if simulate_failure else 0
    die_level = "alerta" if simulate_failure else "info"

    stages = [
        (
            "create",
            0,
            "info",
            "contenedor_create",
            {"contenedor": container_name, "funcion": clean_fn, "invocacion": inv_id},
        ),
        (
            "start",
            120,
            "info",
            "contenedor_start",
            {"contenedor": container_name, "funcion": clean_fn, "invocacion": inv_id},
        ),
        (
            "log",
            450,
            die_level,
            "funcion_log",
            {
                "contenedor": container_name,
                "funcion": clean_fn,
                "invocacion": inv_id,
                "mensaje": log_message,
            },
        ),
        (
            "die",
            820,
            die_level,
            "contenedor_die",
            {
                "contenedor": container_name,
                "funcion": clean_fn,
                "invocacion": inv_id,
                "codigo_salida": exit_code,
            },
        ),
        (
            "destroy",
            950,
            "info",
            "contenedor_destroy",
            {
                "contenedor": container_name,
                "funcion": clean_fn,
                "invocacion": inv_id,
                "destruido": True,
            },
        ),
    ]

    result: list[tuple[str, dict]] = []
    for suffix, offset_ms, level, event_type, datos in stages:
        stamp = (t0 + timedelta(milliseconds=offset_ms)).isoformat()
        result.append(
            (
                suffix,
                {
                    "fecha": stamp,
                    "nodo": node,
                    "origen": "funciones-efimeras",
                    "tipo": event_type,
                    "nivel": level,
                    "datos": datos,
                },
            )
        )
    return result
