terraform {
  # 1.9+ is required for cross-variable references inside `validation` blocks.
  required_version = ">= 1.9.0, < 2.0.0"

  required_providers {
    aws = {
      source = "hashicorp/aws"
      # 6.x is required for the per-resource `region` argument (multi-region support).
      version = ">= 6.0.0, < 7.0.0"
    }
  }
}
