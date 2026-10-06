# EKS access entries for a squad cluster — the target of the access proposal
# (docs/aws.md, "Cluster access: access entries").
#
# Three steps, applied through the existing Azure DevOps Terraform pipeline:
#   1. authentication_mode = "API_AND_CONFIG_MAP" on the cluster (in the
#      cluster's own module: see the snippet in README.md). aws-auth keeps
#      working, so nobody loses access on the day. The switch is one-way.
#   2. This module: one access entry per role, each with the narrowest EKS
#      access policy that fits — people get their own SSO roles, the
#      pipeline keeps its own, squads are scoped to their namespaces.
#   3. Once every aws-auth mapping is mirrored here and verified with
#      `bankctl eks access <cluster>`, remove the mappings from aws-auth.
#
# Not validated with `terraform validate` in this repo (no Terraform in its
# CI); run `terraform init && terraform validate` before the first plan.

terraform {
  required_version = ">= 1.5"
  required_providers {
    aws = {
      source  = "hashicorp/aws"
      version = ">= 5.33" # access entries / access policy associations
    }
  }
}

# Identity Center roles in this account, found by permission-set name.
# Their real ARNs carry the /aws-reserved/sso.amazonaws.com/ path.
data "aws_iam_roles" "sso" {
  for_each    = var.sso_access
  name_regex  = "^AWSReservedSSO_${each.key}_[0-9a-f]+$"
  path_prefix = "/aws-reserved/sso.amazonaws.com/"
}

locals {
  # The path is a known cause of aws-auth mappings that silently never
  # match. Whether access entries need it removed is item 1 of the dev
  # test plan; flip strip_sso_path after that test.
  sso_principals = {
    for set, access in var.sso_access : set => {
      arn = var.strip_sso_path ? replace(one(data.aws_iam_roles.sso[set].arns), "/aws-reserved/sso.amazonaws.com/", "/") : one(data.aws_iam_roles.sso[set].arns)
      access = access
    }
  }
  policy_arn = {
    admin = "arn:aws:eks::aws:cluster-access-policy/AmazonEKSClusterAdminPolicy"
    edit  = "arn:aws:eks::aws:cluster-access-policy/AmazonEKSEditPolicy"
    view  = "arn:aws:eks::aws:cluster-access-policy/AmazonEKSViewPolicy"
  }
}

# --- people: one entry per Identity Center permission set ---------------

resource "aws_eks_access_entry" "sso" {
  for_each      = local.sso_principals
  cluster_name  = var.cluster_name
  principal_arn = each.value.arn
  type          = "STANDARD"
}

resource "aws_eks_access_policy_association" "sso" {
  for_each      = local.sso_principals
  cluster_name  = var.cluster_name
  principal_arn = each.value.arn
  policy_arn    = local.policy_arn[each.value.access.policy]

  access_scope {
    type       = length(each.value.access.namespaces) > 0 ? "namespace" : "cluster"
    namespaces = each.value.access.namespaces
  }

  depends_on = [aws_eks_access_entry.sso]
}

# --- the Azure DevOps pipeline: its own entry, separate from people -------

resource "aws_eks_access_entry" "pipeline" {
  cluster_name  = var.cluster_name
  principal_arn = var.pipeline_role_arn
  type          = "STANDARD"
}

resource "aws_eks_access_policy_association" "pipeline" {
  cluster_name  = var.cluster_name
  principal_arn = var.pipeline_role_arn
  policy_arn    = local.policy_arn[var.pipeline_policy]

  access_scope {
    type = "cluster"
  }

  depends_on = [aws_eks_access_entry.pipeline]
}
