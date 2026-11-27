# Modelo de amenazas (inicial)

## Activos

- Ledger JSONL, hash anterior y hashes SHA-256.
- Clave Ed25519 privada, contador y registro de `request_id` del firmador.
- Clave pública confiable, estado local de anclas, identidad de despliegue y datos QBFT persistentes.
- Contrato, métricas e inventario Terraform/Ansible.

## Límites de confianza

- El host que controla Docker y sus volúmenes es autoridad sobre el demo local.
- El usuario que controla el firmador genera/retiene identidades; no existe hardware seguro o atestación remota.
- La cuenta de despliegue autoriza un emisor por nombre de nodo. El contrato aplica autorización, no la identidad del evento.
- El verificador confía explícitamente en la clave pública suministrada; una firma válida no prueba quién controlaba el sistema ni cuándo ocurrió el hecho.
- Proxmox y su red no quedan bajo control automático de este código.

## Riesgos tratados parcialmente

- Modificación o reordenación de eventos: hash encadenado y comprobación estricta del ledger.
- Firma alterada, ausente o sin clave confiable: autenticidad reportada aparte; no se declara evidencia completa.
- Pérdida de respuesta a una solicitud de firma: reintento con ID estable devuelve el resultado persistido sin incrementar otra vez.
- Contador/state corrupto o ausente: el firmador falla cerrado cuando falta el estado asociado a una clave existente.
- Regresión remota/local de contador o ancla con huecos: anclador/verificador rechazan regresión y prefijos no contiguos.
- RPC/contrato mal desplegado: comparación del hash de fuente y bytecode runtime compilado con el bytecode consultado.
- Puertos locales: bindings loopback por defecto; reglas efectivas del host siguen siendo responsabilidad del operador.

## Fuera de alcance

Compromiso del kernel/host, abuso por root, cadena de suministro completa, bloqueo administrativo del validador, ataques de mayoría, garantías de tiempo, retención a largo plazo, recuperación ante desastre probada, privacidad de datos, mitigación de denegación de servicio, análisis forense y seguridad SGX. La demo de un validador no mitiga censura ni pérdida del monitor.
