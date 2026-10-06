variable "cluster_name" {
  description = "EKS cluster name."
  type        = string
}

variable "sso_access" {
  description = <<-EOT
    Identity Center permission set name => EKS access. policy is admin, edit
    or view; namespaces empty = whole cluster. Example for a prod cluster:
      Platform-ReadOnly = { policy = "view",  namespaces = [] }
      BreakGlass-Admin  = { policy = "admin", namespaces = [] }
      Squad-Payments    = { policy = "edit",  namespaces = ["payments"] }
  EOT
  type = map(object({
    policy     = string
    namespaces = list(string)
  }))

  validation {
    condition     = alltrue([for a in values(var.sso_access) : contains(["admin", "edit", "view"], a.policy)])
    error_message = "policy must be admin, edit or view."
  }
}

variable "pipeline_role_arn" {
  description = "The Azure DevOps deployment role (devops role). Only the pipeline should be able to assume it."
  type        = string
}

variable "pipeline_policy" {
  description = "EKS access policy for the pipeline: admin, edit or view."
  type        = string
  default     = "admin"

  validation {
    condition     = contains(["admin", "edit", "view"], var.pipeline_policy)
    error_message = "pipeline_policy must be admin, edit or view."
  }
}

variable "strip_sso_path" {
  description = "Map SSO roles by ARN without /aws-reserved/sso.amazonaws.com/ (decide after the dev test)."
  type        = bool
  default     = false
}
