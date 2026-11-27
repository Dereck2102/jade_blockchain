# Contribuir

Las contribuciones pequeñas, revisables y reproducibles son bienvenidas. No conectes cambios o runners públicos con el laboratorio ni uses datos, credenciales o eventos reales.

## Desarrollo local

Requisitos: Python 3.12, Node.js/npm compatibles con `chain/package-lock.json`, Docker Compose v2 para la integración y herramientas Terraform/Ansible para validar infraestructura.

```sh
python3.12 -m venv .venv
. .venv/bin/activate
python -m pip install .
python -m unittest discover -s tests -v

npm ci --prefix chain
npm audit --prefix chain --audit-level=low
npm test --prefix chain
npm run --prefix chain compile

docker compose config --quiet
terraform fmt -check -recursive infrastructure/proxmox
terraform -chdir=infrastructure/proxmox init -backend=false
terraform -chdir=infrastructure/proxmox validate
(cd ansible && ansible-playbook --syntax-check -i inventory/example.yml site.yml)
```

Para la demostración, sigue el inicio rápido del README. El stack descarga imágenes y crea identidades locales; no ejecutes `terraform apply` en una infraestructura que no hayas autorizado.

## Cambios y pull requests

- Añade pruebas focalizadas para nuevas reglas de serialización, firma, contador, cobertura de ancla o autorización.
- Mantén compatible la serialización v1. Un cambio incompatible requiere una versión nueva de esquema y nota de migración.
- Declara qué fue implementado, qué se probó realmente y qué sigue pendiente; identifica explícitamente cualquier mock.
- No incluyas claves, `.env`, state/planes Terraform, backups, logs reales, datos personales ni tokens.
- CI de pull request no requiere secretos y no tiene credenciales ni ruta de red al laboratorio.
- Revisa los avisos/licencias de dependencias nuevas y conserva sus avisos aplicables.
