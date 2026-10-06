output "principals" {
  description = "Principal ARN => EKS policy, for review alongside `bankctl eks access <cluster>`."
  value = merge(
    { for set, p in local.sso_principals : p.arn => p.access.policy },
    { (var.pipeline_role_arn) = var.pipeline_policy },
  )
}
