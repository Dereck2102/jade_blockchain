locals {
  roles = ["monitor", "node-1", "node-2"]
}

resource "proxmox_virtual_environment_container" "jade" {
  count        = 3
  description  = "JaDe Blockchain ${local.roles[count.index]} - gestionado por Terraform"
  node_name    = var.proxmox_node
  vm_id        = var.container_ids[count.index]
  unprivileged = true

  features {
    nesting = true
  }

  cpu {
    cores = var.cpu_cores
  }

  memory {
    dedicated = var.memory_mb
  }

  initialization {
    hostname = "jade-${local.roles[count.index]}"

    ip_config {
      ipv4 {
        address = var.ipv4_addresses[count.index]
        gateway = var.ipv4_gateway
      }
    }

    user_account {
      keys = var.ssh_public_keys
    }
  }

  network_interface {
    name   = "eth0"
    bridge = var.bridge
  }

  disk {
    datastore_id = var.storage_id
    size         = var.root_disk_gb
  }

  operating_system {
    template_file_id = var.template_file_id
    type             = "debian"
  }

  lifecycle {
    prevent_destroy = true
  }
}

output "ansible_inventory" {
  description = "Inventario YAML para Ansible; guardar explícitamente tras revisar la salida."
  value = yamlencode({
    all = {
      children = {
        monitor = {
          hosts = {
            "jade-monitor" = {
              ansible_host = split("/", var.ipv4_addresses[0])[0]
              ansible_user = "root"
            }
          }
        }
        nodes = {
          hosts = {
            for index in [1, 2] : "jade-node-${index}" => {
              ansible_host = split("/", var.ipv4_addresses[index])[0]
              ansible_user = "root"
            }
          }
        }
      }
    }
  })
}
