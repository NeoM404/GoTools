# EKS access entries

Moves a squad cluster from the `aws-auth` ConfigMap to EKS access entries,
without anyone losing access on the day.

## 1. Enable access entries on the cluster (one-way)

In the cluster's own Terraform, through the existing Azure DevOps pipeline:

```hcl
resource "aws_eks_cluster" "this" {
  # ...
  access_config {
    authentication_mode                         = "API_AND_CONFIG_MAP"
    bootstrap_cluster_creator_admin_permissions = false
  }
}
```

`aws-auth` keeps working in `API_AND_CONFIG_MAP`. A cluster cannot go back
to `CONFIG_MAP` afterwards. Start with dev clusters.

## 2. Grant access per role (this module)

```hcl
module "payments_prod_access" {
  source            = "../../deploy/terraform/eks-access-entries"
  cluster_name      = "payments-eks-prod"
  pipeline_role_arn = "arn:aws:iam::111111111111:role/devops-pipeline"
  sso_access = {
    "Platform-ReadOnly" = { policy = "view", namespaces = [] }
    "BreakGlass-Admin"  = { policy = "admin", namespaces = [] }
    "Squad-Payments"    = { policy = "edit", namespaces = ["payments"] }
  }
}
```

## 3. Verify, then retire aws-auth

```bash
nedctl eks auth --all-profiles          # which clusters still need step 1
nedctl eks access payments-eks-prod     # who can reach it, with which policy
```

Remove a mapping from `aws-auth` only after its access entry is verified.

## Before the first apply

- Run `terraform init && terraform validate` (this module has not been
  validated in this repo's CI).
- In dev, check whether SSO role ARNs must be given with or without the
  `/aws-reserved/sso.amazonaws.com/` path (`strip_sso_path`).
