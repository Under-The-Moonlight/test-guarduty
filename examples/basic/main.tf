provider "aws" {
  # Falls back to AWS_REGION / the active profile when not set.
  region = var.region
}

# Minimal call: detector with the default protection plans, encrypted S3 export
# and an SNS topic for High/Critical findings.
module "guardduty" {
  source = "../../modules/guardduty"
}
