# Operación

## Demo local

1. Revisa Docker/Compose y puertos; copia `.env.example` a `.env` solo si necesitas personalizar números de puerto.
2. `docker compose --profile synthetic build`
3. `docker compose up -d besu contract metrics`
4. Genera, ancla y verifica con los comandos del README.
5. `docker compose --profile observability up -d prometheus grafana` habilita monitoreo opcional.
6. `docker compose ps -a`, `docker compose logs besu contract metrics` para revisar estado.

Besu, Prometheus, Grafana y métricas se vinculan a `127.0.0.1`. Docker, UFW y reglas IPv6 pueden interactuar; comprueba el firewall efectivo del host antes de usarlo, también si se cambia un puerto. No montes el socket Docker del anfitrión: la demo no lo requiere ni captura sus eventos.

Los volúmenes de datos conservan los eventos, clave/contador/request IDs, genesis, contrato y datos de Besu tras recrear contenedores. `docker compose down` no elimina volúmenes. No uses `down --volumes` como actualización o limpieza rutinaria.

## Creación inicial de una réplica nueva

1. Confirma acceso autorizado a un nodo Proxmox, almacenamiento, bridge existente, plantilla LXC Debian 12 y segmento de red. El módulo no crea bridges ni configura OPNsense.
2. Copia `infrastructure/proxmox/terraform.tfvars.example` a un fichero local ignorado/no versionado. Sustituye todo placeholder por valores revisados. IDs deben estar libres; direcciones estáticas deben reservarse.
3. Inicializa y revisa el plan:

   ```sh
   terraform -chdir=infrastructure/proxmox init
   terraform -chdir=infrastructure/proxmox fmt -check
   terraform -chdir=infrastructure/proxmox validate
   terraform -chdir=infrastructure/proxmox plan -out=terraform.tfplan
   ```

4. Revisa el plan contra el entorno y crea solamente los recursos nuevos autorizados mediante `terraform -chdir=infrastructure/proxmox apply terraform.tfplan`. No se importan ni adoptan recursos existentes; `prevent_destroy` bloquea destruir los tres contenedores gestionados.
5. Genera y revisa inventario antes de conectar Ansible:

   ```sh
   terraform -chdir=infrastructure/proxmox output -raw ansible_inventory > ansible/inventory/generated.yml
   ansible-playbook -i ansible/inventory/generated.yml ansible/site.yml
   ```

El inventario generado incluye direcciones solicitadas y usuario root para la clave inicial; pasa una clave privada SSH local mediante configuración de Ansible, nunca la guardes en el repositorio. La unidad desplegada solo expone métricas localhost. El rol no instala un inspector real.

## Actualización

Actualiza el código/servicios con cambios revisados, respaldos previos y pruebas; no borres volúmenes. Para Terraform, usa un state existente protegido, revisa `plan` y conserva `prevent_destroy`. No importes recursos del laboratorio previo ni apliques en CI. `sensitive` solo oculta valores en salida y no cifra el state en disco.

## Estado y separación de herramientas

- Terraform: infraestructura nueva y state.
- Ansible: paquetes/sistema/systemd de Debian.
- Compose: contenedores y servicios de demostración.

No se usan provisioners Terraform para configuración. CI de pull requests no accede al hipervisor, red privada o credenciales.

Para respaldar o restaurar, sigue [RESTORE.md](RESTORE.md), no improvises con volúmenes activos.
