# terraform-aws-guardduty

Reusable Terraform module that enables and configures **Amazon GuardDuty** in an AWS account with a secure baseline:

- **Detector** with a configurable findings publishing frequency.
- **Protection plans**, each toggled by its own variable: S3 Protection, EKS Audit Log Monitoring,
  EKS Runtime Monitoring (with agent management), RDS Login Activity Monitoring, Malware Protection for EC2.
- **Findings export to S3**: dedicated bucket encrypted with SSE-KMS (module-created or your own key), least-privilege
  bucket and key policies, public access blocked, TLS enforced, versioning and a lifecycle policy.
- **Alerts**: EventBridge rule matching findings at or above a severity threshold, delivered to a KMS-encrypted SNS topic
  (optionally with email subscriptions).
- **Suppression rules**: GuardDuty filters defined as a list of objects.
- **Bonus**: multi-region deployment with a single provider, AWS Organizations mode (delegated administrator +
  auto-enable of member accounts), `terraform test` unit tests, pre-commit hooks and a GitHub Actions pipeline
  (fmt, validate, test, tflint, checkov, terraform-docs).

```text
                       ┌───────────────────────────┐
                       │     GuardDuty detector    │──── suppression rules (aws_guardduty_filter)
                       │  + protection features    │
                       └──────┬─────────────┬──────┘
          publishing destination│             │ "GuardDuty Finding" events
                                ▼             ▼
            ┌───────────────────────┐   ┌──────────────────────────────┐
            │ S3 bucket (SSE-KMS)   │   │ EventBridge rule             │
            │ - public access block │   │ detail.severity >= threshold │
            │ - TLS-only policy     │   └──────────────┬───────────────┘
            │ - versioning          │                  ▼
            │ - lifecycle           │   ┌──────────────────────────────┐
            └───────────┬───────────┘   │ SNS topic (KMS-encrypted)    │──► email / chat / SIEM
                        │               └──────────────┬───────────────┘
                        └──────────► KMS key ◄─────────┘
                                (rotation enabled)
```

## Repository layout

```text
modules/guardduty/                core module (account / region level)
  main.tf  variables.tf  outputs.tf  versions.tf
  tests/guardduty.tftest.hcl      offline unit tests (mock provider)
modules/guardduty-organization/   optional: delegated admin + auto-enable for an AWS Organization
examples/basic/                   minimal call                       (+ plan.txt)
examples/complete/                every option enabled               (+ plan.txt)
examples/multi-region/            one module instance per region     (+ plan.txt)
examples/organization/            delegated administrator setup      (+ plan.txt)
```

## Usage

### Minimal

```hcl
module "guardduty" {
  source = "git::https://github.com/<org>/terraform-aws-guardduty.git//modules/guardduty?ref=v1.0.0"
}
```

With the defaults this creates a detector (publishing every 15 minutes) with S3 Protection, EKS Audit Logs, RDS Login
Activity and EC2 Malware Protection enabled, exports findings to `guardduty-findings-<account>-<region>` encrypted with a
new KMS key and publishes High/Critical findings (severity >= 7) to the `guardduty-findings-alert` SNS topic.

### Typical

```hcl
module "guardduty" {
  source = "git::https://github.com/<org>/terraform-aws-guardduty.git//modules/guardduty?ref=v1.0.0"

  enable_eks_runtime_monitoring = true
  runtime_monitoring_agent_management = {
    eks_addon = true # GuardDuty installs and updates the aws-guardduty-agent add-on
  }

  alert_severity_threshold = 4 # Medium and above
  alert_email_addresses    = ["security@example.com"]

  findings_retention_days          = 730
  findings_glacier_transition_days = 90

  suppression_rules = [
    {
      name        = "archive-trusted-scanner"
      description = "Port probes from the internal vulnerability scanner"
      criteria = [
        { field = "type", equals = ["Recon:EC2/PortProbeUnprotectedPort"] },
        { field = "service.action.networkConnectionAction.remoteIpDetails.ipAddressV4", equals = ["198.51.100.10"] },
      ]
    },
  ]

  tags = { Team = "security" }
}
```

### Bring your own KMS key

```hcl
module "guardduty" {
  source = "../../modules/guardduty"

  create_kms_key = false
  kms_key_arn    = aws_kms_key.security.arn
}
```

The key must live in the same region as the bucket and its policy must contain the statements returned by the
`kms_key_policy_statements_json` output (GuardDuty `kms:GenerateDataKey` scoped to the detector, and EventBridge access
for the encrypted SNS topic). A typical way is to merge them with `source_policy_documents` in the key policy.

### Multi-region

AWS provider 6.x has a per-resource `region` argument, so a single provider is enough:

```hcl
module "guardduty" {
  source   = "../../modules/guardduty"
  for_each = toset(["eu-central-1", "eu-west-1", "us-east-1"])

  region = each.key
}
```

Every region gets its own detector, bucket, key and topic (GuardDuty is regional; the KMS key must be in the bucket's
region). See [`examples/multi-region`](examples/multi-region).

### AWS Organizations

[`modules/guardduty-organization`](modules/guardduty-organization) designates the account in which the core module runs
as the GuardDuty **delegated administrator** (call made from the management account through the `aws.management`
provider) and configures auto-enable of the detector and of the same protection plans for member accounts
(`ALL` / `NEW` / `NONE`). Findings of all members are aggregated into the administrator account, so the export bucket
and the alert rule of the core module cover the whole organization. See [`examples/organization`](examples/organization).

Prerequisite: trusted access for `guardduty.amazonaws.com` must be enabled in AWS Organizations. When auto-enable is
used, do not deploy the core module in member accounts — their detectors and features are owned by the administrator.

## Design decisions

| Topic | Decision |
| ----- | -------- |
| Feature management | Features are managed with `aws_guardduty_detector_feature` (the `datasources` block is deprecated). Every feature is always set explicitly to `ENABLED` or `DISABLED`, so the result never depends on what AWS enables by default on new detectors. |
| EKS Runtime Monitoring | Implemented through the `RUNTIME_MONITORING` feature, which superseded `EKS_RUNTIME_MONITORING` (the two cannot be enabled at the same time). Agent management is configured per platform: `EKS_ADDON_MANAGEMENT` (default on), ECS Fargate and EC2 (default off). Runtime Monitoring itself is opt-in because it deploys an agent into the clusters. |
| Bucket policy | GuardDuty may only `s3:GetBucketLocation` / `s3:PutObject` with `aws:SourceAccount` + `aws:SourceArn` = this detector (confused-deputy protection). Uploads without SSE-KMS or with a different key are denied, and every non-TLS request is denied. ACLs are disabled (`BucketOwnerEnforced`) and all public access is blocked. |
| Key policy | The AWS default root statement (delegates key access to IAM in the same account, prevents an unmanageable key), GuardDuty `kms:GenerateDataKey` scoped to this detector, and `kms:GenerateDataKey`/`kms:Decrypt` for EventBridge (required to publish to an encrypted SNS topic). Rotation is enabled. |
| SNS encryption | The topic uses the customer managed key: the AWS managed `alias/aws/sns` key cannot be used by EventBridge because its policy can't be changed. The topic policy only lets this EventBridge rule (`aws:SourceArn`) publish and denies non-TLS publishing. |
| Lifecycle | Findings go to Glacier Flexible Retrieval after 90 days and expire after 365 days by default; noncurrent versions are removed after 30 days; incomplete multipart uploads after 7 days. |
| Severity threshold | Numeric (1-10) and matched with an EventBridge `numeric` filter (`>=`), so it also covers the Critical range (9.0-10.0) of Extended Threat Detection. |
| Suppression rules | The list order is the filter rank, so ranks are never duplicated or out of sync. `action` defaults to `ARCHIVE` (suppression); `NOOP` creates a saved filter. |
| No hardcoding | Account ID, partition and region come from data sources; there are no account IDs, regions or secrets in the module code. |
| Versions | The module sets a lower bound and a major cap (`>= 1.9` Terraform, `>= 6.0, < 7.0` AWS provider) so it can be consumed by different root modules. The examples (root modules) pin the provider with `~> 6.67`, and the committed `.terraform.lock.hcl` locks the exact version and checksums. |

## Validation and plans

All checks pass locally with Terraform 1.16.4, tflint 0.64.0 (+ AWS ruleset 0.49.0) and checkov:

```bash
mise install                                   # installs the pinned tool versions from mise.toml
terraform fmt -check -recursive
terraform -chdir=examples/complete init -backend=false && terraform -chdir=examples/complete validate
terraform -chdir=modules/guardduty init -backend=false && terraform -chdir=modules/guardduty test
tflint --init && tflint --recursive --config "$PWD/.tflint.hcl"
checkov -d . --framework terraform
```

`terraform plan` output for every example is stored next to it in `plan.txt`. They were generated with:

```bash
terraform -chdir=examples/basic plan -no-color > examples/basic/plan.txt
terraform -chdir=examples/complete plan -no-color > examples/complete/plan.txt
terraform -chdir=examples/multi-region plan -no-color -var 'regions=["eu-central-1","eu-west-1"]' > examples/multi-region/plan.txt
terraform -chdir=examples/organization plan -no-color -var 'delegated_admin_role_arn=arn:aws:iam::210987654321:role/terraform' > examples/organization/plan.txt
```

> **Note:** the committed plans were generated in `eu-central-1` without a real AWS account: the only API the plan calls
> is STS (`aws_caller_identity`, and `AssumeRole` in the organization example), which was served by a local
> [moto](https://github.com/getmoto/moto) server (`AWS_ENDPOINT_URL_STS=http://localhost:5055`). That's why the account
> ID is `123456789012`. Running the same commands with real credentials produces the same plan with your account ID.

Unit tests (`modules/guardduty/tests`) use `mock_provider` and run fully offline. They cover the defaults, feature
toggles, runtime agent management, external KMS key, disabled export/alerts, suppression rules, policy scoping and the
input validations.

# Module reference: `modules/guardduty`

<!-- BEGIN_TF_DOCS -->
## Requirements

| Name | Version |
| ---- | ------- |
| terraform | >= 1.9.0, < 2.0.0 |
| aws | >= 6.0.0, < 7.0.0 |

## Providers

| Name | Version |
| ---- | ------- |
| aws | >= 6.0.0, < 7.0.0 |

## Modules

No modules.

## Resources

| Name | Type |
| ---- | ---- |
| [aws_cloudwatch_event_rule.findings](https://registry.terraform.io/providers/hashicorp/aws/latest/docs/resources/cloudwatch_event_rule) | resource |
| [aws_cloudwatch_event_target.sns](https://registry.terraform.io/providers/hashicorp/aws/latest/docs/resources/cloudwatch_event_target) | resource |
| [aws_guardduty_detector.this](https://registry.terraform.io/providers/hashicorp/aws/latest/docs/resources/guardduty_detector) | resource |
| [aws_guardduty_detector_feature.this](https://registry.terraform.io/providers/hashicorp/aws/latest/docs/resources/guardduty_detector_feature) | resource |
| [aws_guardduty_filter.this](https://registry.terraform.io/providers/hashicorp/aws/latest/docs/resources/guardduty_filter) | resource |
| [aws_guardduty_publishing_destination.this](https://registry.terraform.io/providers/hashicorp/aws/latest/docs/resources/guardduty_publishing_destination) | resource |
| [aws_kms_alias.this](https://registry.terraform.io/providers/hashicorp/aws/latest/docs/resources/kms_alias) | resource |
| [aws_kms_key.this](https://registry.terraform.io/providers/hashicorp/aws/latest/docs/resources/kms_key) | resource |
| [aws_s3_bucket.findings](https://registry.terraform.io/providers/hashicorp/aws/latest/docs/resources/s3_bucket) | resource |
| [aws_s3_bucket_lifecycle_configuration.findings](https://registry.terraform.io/providers/hashicorp/aws/latest/docs/resources/s3_bucket_lifecycle_configuration) | resource |
| [aws_s3_bucket_logging.findings](https://registry.terraform.io/providers/hashicorp/aws/latest/docs/resources/s3_bucket_logging) | resource |
| [aws_s3_bucket_ownership_controls.findings](https://registry.terraform.io/providers/hashicorp/aws/latest/docs/resources/s3_bucket_ownership_controls) | resource |
| [aws_s3_bucket_policy.findings](https://registry.terraform.io/providers/hashicorp/aws/latest/docs/resources/s3_bucket_policy) | resource |
| [aws_s3_bucket_public_access_block.findings](https://registry.terraform.io/providers/hashicorp/aws/latest/docs/resources/s3_bucket_public_access_block) | resource |
| [aws_s3_bucket_server_side_encryption_configuration.findings](https://registry.terraform.io/providers/hashicorp/aws/latest/docs/resources/s3_bucket_server_side_encryption_configuration) | resource |
| [aws_s3_bucket_versioning.findings](https://registry.terraform.io/providers/hashicorp/aws/latest/docs/resources/s3_bucket_versioning) | resource |
| [aws_sns_topic.this](https://registry.terraform.io/providers/hashicorp/aws/latest/docs/resources/sns_topic) | resource |
| [aws_sns_topic_policy.this](https://registry.terraform.io/providers/hashicorp/aws/latest/docs/resources/sns_topic_policy) | resource |
| [aws_sns_topic_subscription.email](https://registry.terraform.io/providers/hashicorp/aws/latest/docs/resources/sns_topic_subscription) | resource |
| [aws_caller_identity.current](https://registry.terraform.io/providers/hashicorp/aws/latest/docs/data-sources/caller_identity) | data source |
| [aws_iam_policy_document.findings_bucket](https://registry.terraform.io/providers/hashicorp/aws/latest/docs/data-sources/iam_policy_document) | data source |
| [aws_iam_policy_document.kms](https://registry.terraform.io/providers/hashicorp/aws/latest/docs/data-sources/iam_policy_document) | data source |
| [aws_iam_policy_document.kms_service_access](https://registry.terraform.io/providers/hashicorp/aws/latest/docs/data-sources/iam_policy_document) | data source |
| [aws_iam_policy_document.sns](https://registry.terraform.io/providers/hashicorp/aws/latest/docs/data-sources/iam_policy_document) | data source |
| [aws_partition.current](https://registry.terraform.io/providers/hashicorp/aws/latest/docs/data-sources/partition) | data source |
| [aws_region.current](https://registry.terraform.io/providers/hashicorp/aws/latest/docs/data-sources/region) | data source |

## Inputs

| Name | Description | Type | Default | Required |
| ---- | ----------- | ---- | ------- | :------: |
| alert\_email\_addresses | Email addresses subscribed to the alerts SNS topic. Each address has to confirm the subscription. | `list(string)` | `[]` | no |
| alert\_severity\_threshold | Minimum finding severity that triggers an alert. GuardDuty severity ranges: Low 1.0-3.9, Medium 4.0-6.9, High 7.0-8.9, Critical 9.0-10.0. | `number` | `7` | no |
| create\_kms\_key | Create a customer managed KMS key used to encrypt the findings bucket and the SNS topic. When `false`, `kms_key_arn` must be provided. | `bool` | `true` | no |
| create\_sns\_topic | Create the SNS topic for alerts. When `false`, `sns_topic_arn` must be provided and its topic policy must allow `events.amazonaws.com` to publish. | `bool` | `true` | no |
| enable\_alerts | Create an EventBridge rule that forwards findings at or above `alert_severity_threshold` to SNS. | `bool` | `true` | no |
| enable\_ec2\_malware\_protection | Enable GuardDuty-initiated Malware Protection for EC2 (EBS volume scanning, feature EBS\_MALWARE\_PROTECTION). | `bool` | `true` | no |
| enable\_eks\_audit\_log\_monitoring | Enable EKS Audit Log Monitoring (feature EKS\_AUDIT\_LOGS). | `bool` | `true` | no |
| enable\_eks\_runtime\_monitoring | Enable EKS Runtime Monitoring (feature RUNTIME\_MONITORING). Requires the GuardDuty security agent on the clusters, see `runtime_monitoring_agent_management`. | `bool` | `false` | no |
| enable\_rds\_login\_activity\_monitoring | Enable RDS Login Activity Monitoring for Aurora / RDS databases (feature RDS\_LOGIN\_EVENTS). | `bool` | `true` | no |
| enable\_s3\_export | Export findings to a KMS-encrypted S3 bucket created by the module. | `bool` | `true` | no |
| enable\_s3\_protection | Enable S3 Protection (monitoring of S3 data events, feature S3\_DATA\_EVENTS). | `bool` | `true` | no |
| finding\_publishing\_frequency | How often updates to existing findings are published to EventBridge and S3. New findings are always exported within ~5 minutes. | `string` | `"FIFTEEN_MINUTES"` | no |
| findings\_glacier\_transition\_days | Number of days after which exported findings are transitioned to S3 Glacier Flexible Retrieval. Set to `null` to disable the transition. | `number` | `90` | no |
| findings\_noncurrent\_version\_retention\_days | Number of days noncurrent (overwritten or deleted) object versions are kept before permanent deletion. | `number` | `30` | no |
| findings\_retention\_days | Number of days after which exported findings are expired from the bucket. | `number` | `365` | no |
| kms\_key\_arn | ARN of an existing KMS key to use when `create_kms_key = false`. Its key policy must contain the statements from the `kms_key_policy_statements_json` output. | `string` | `null` | no |
| kms\_key\_deletion\_window\_in\_days | Waiting period before the module-created KMS key is deleted after `terraform destroy`. | `number` | `30` | no |
| name | Name prefix used for all resources created by the module (S3 bucket, KMS alias, SNS topic, EventBridge rule). | `string` | `"guardduty"` | no |
| region | AWS region to deploy into. Defaults to the region configured on the provider. Set it (together with `for_each` on the module) to deploy into several regions with a single provider. | `string` | `null` | no |
| runtime\_monitoring\_agent\_management | Controls whether GuardDuty automatically deploys and manages its security agent when Runtime Monitoring is enabled. `eks_addon`   - manage the `aws-guardduty-agent` EKS add-on on all clusters (EKS\_ADDON\_MANAGEMENT). `ecs_fargate` - manage the sidecar agent for ECS Fargate tasks (ECS\_FARGATE\_AGENT\_MANAGEMENT). `ec2`         - manage the agent on EC2 instances through SSM (EC2\_AGENT\_MANAGEMENT). Set `eks_addon = false` if you deploy the agent yourself (e.g. via Terraform/Helm per cluster). | ```object({ eks_addon = optional(bool, true) ecs_fargate = optional(bool, false) ec2 = optional(bool, false) })``` | `{}` | no |
| s3\_access\_logging | Optional server access logging for the findings bucket. `target_bucket` is an existing bucket that accepts S3 server access logs. | ```object({ target_bucket = string target_prefix = optional(string, "guardduty-findings/") })``` | `null` | no |
| s3\_bucket\_name | Name of the findings bucket. Defaults to `<name>-findings-<account_id>-<region>`. | `string` | `null` | no |
| s3\_force\_destroy | Allow Terraform to delete the findings bucket even if it still contains objects. Keep `false` outside of test environments. | `bool` | `false` | no |
| sns\_topic\_arn | ARN of an existing SNS topic to send alerts to when `create_sns_topic = false`. | `string` | `null` | no |
| suppression\_rules | GuardDuty filters. The list order defines the filter rank (first element = rank 1). `action` is `ARCHIVE` (suppression rule: matching findings are auto-archived) or `NOOP` (saved filter only). Each `criteria` element targets one finding attribute (`field`, e.g. `type`, `severity`, `resource.instanceDetails.tags.value`) and sets at least one comparison operator. See https://docs.aws.amazon.com/guardduty/latest/ug/guardduty_filter-findings.html for the list of fields. | ```list(object({ name = string description = optional(string) action = optional(string, "ARCHIVE") criteria = list(object({ field = string equals = optional(list(string)) not_equals = optional(list(string)) matches = optional(list(string)) not_matches = optional(list(string)) greater_than = optional(string) greater_than_or_equal = optional(string) less_than = optional(string) less_than_or_equal = optional(string) })) }))``` | `[]` | no |
| tags | Tags applied to every taggable resource created by the module. | `map(string)` | `{}` | no |

## Outputs

| Name | Description |
| ---- | ----------- |
| detector\_arn | ARN of the GuardDuty detector. |
| detector\_id | ID of the GuardDuty detector. |
| eventbridge\_rule\_arn | ARN of the EventBridge rule matching findings above the severity threshold (null when alerts are disabled). |
| features | Map of managed GuardDuty features to their desired state. Can be passed to the `guardduty-organization` module. |
| kms\_key\_arn | ARN of the KMS key used for the findings bucket and the SNS topic (module-created or passed in). |
| kms\_key\_policy\_statements\_json | Key policy statements GuardDuty and EventBridge need on the KMS key. Merge them into the policy of an externally managed key (`create_kms_key = false`). |
| s3\_bucket\_arn | ARN of the S3 bucket that receives exported findings (null when export is disabled). |
| s3\_bucket\_name | Name of the S3 bucket that receives exported findings (null when export is disabled). |
| sns\_topic\_arn | ARN of the SNS topic that receives alerts (null when alerts are disabled). |
| suppression\_rule\_ids | Map of suppression rule (filter) name to its resource ID. |
<!-- END_TF_DOCS -->
