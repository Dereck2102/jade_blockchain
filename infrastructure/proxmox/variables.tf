variable "proxmox_endpoint" {
  description = "URL del API Proxmox del laboratorio nuevo."
  type        = string
}

variable "proxmox_api_token" {
  description = "Token del proveedor Proxmox, suministrado fuera del repositorio."
  type        = string
  sensitive   = true
}

variable "proxmox_node" {
  description = "Nombre del nodo Proxmox que recibirá los nuevos contenedores."
  type        = string
}

variable "container_ids" {
  description = "Tres IDs libres, nuevos y distintos para monitor y nodos."
  type        = list(number)

  validation {
    condition     = length(var.container_ids) == 3 && length(distinct(var.container_ids)) == 3 && alltrue([for id in var.container_ids : id >= 100 && id == floor(id)])
    error_message = "Indica exactamente tres IDs LXC distintos, mayores o iguales a 100."
  }
}

variable "template_file_id" {
  description = "ID de una plantilla LXC Debian 12 existente, por ejemplo local:vztmpl/debian-12-standard_12.7-1_amd64.tar.zst."
  type        = string
}

variable "storage_id" {
  description = "ID de almacenamiento permitido para los volúmenes nuevos."
  type        = string
}

variable "bridge" {
  description = "Bridge existente que el administrador haya autorizado."
  type        = string
}

variable "ipv4_addresses" {
  description = "Tres direcciones IPv4 CIDR estáticas reservadas; necesarias para el inventario Ansible."
  type        = list(string)

  validation {
    condition     = length(var.ipv4_addresses) == 3 && alltrue([for address in var.ipv4_addresses : can(cidrhost(address, 0))])
    error_message = "Proporciona tres direcciones IPv4 CIDR estáticas válidas y reservadas."
  }
}

variable "ipv4_gateway" {
  description = "Gateway de la red, requerido para direcciones estáticas."
  type        = string
}

variable "ssh_public_keys" {
  description = "Claves públicas SSH de los administradores del laboratorio."
  type        = list(string)

  validation {
    condition     = length(var.ssh_public_keys) > 0 && alltrue([for key in var.ssh_public_keys : can(regex("^ssh-(ed25519|rsa|ecdsa)", key))])
    error_message = "Proporciona al menos una clave pública SSH válida."
  }
}

variable "cpu_cores" {
  description = "Núcleos asignados a cada LXC nuevo."
  type        = number
  default     = 2

  validation {
    condition     = var.cpu_cores >= 1 && var.cpu_cores <= 32
    error_message = "cpu_cores debe estar entre 1 y 32."
  }
}

variable "memory_mb" {
  description = "Memoria asignada a cada LXC nuevo."
  type        = number
  default     = 2048

  validation {
    condition     = var.memory_mb >= 512
    error_message = "memory_mb debe ser al menos 512."
  }
}

variable "root_disk_gb" {
  description = "Tamaño del filesystem root de cada LXC nuevo."
  type        = number
  default     = 16

  validation {
    condition     = var.root_disk_gb >= 8
    error_message = "root_disk_gb debe ser al menos 8 GB."
  }
}
