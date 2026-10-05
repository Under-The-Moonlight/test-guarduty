# guardduty-organization

Optional companion of the [`guardduty`](../guardduty) module for AWS Organizations:

1. designates the account behind the default `aws` provider as the GuardDuty **delegated administrator**
   (`aws_guardduty_organization_admin_account`, executed in the management account via `aws.management`);
2. configures auto-enable of GuardDuty for member accounts (`ALL`, `NEW` or `NONE`);
3. auto-enables the same protection plans (and runtime agent management) that are enabled on the administrator's
   detector, using the `features` output of the core module.

GuardDuty organization settings are regional: call the module once per region (e.g. with `for_each` and `region`).

```hcl
module "guardduty" {
  source = "../guardduty"
}

module "guardduty_organization" {
  source = "../guardduty-organization"

  providers = {
    aws            = aws            # delegated administrator account
    aws.management = aws.management # Organizations management account
  }

  detector_id                      = module.guardduty.detector_id
  features                         = module.guardduty.features
  auto_enable_organization_members = "ALL"
}
```

<!-- BEGIN_TF_DOCS -->
## Requirements

| Name | Version |
| ---- | ------- |
| terraform | >= 1.9.0, < 2.0.0 |
| aws | >= 6.36.0, < 7.0.0 |

## Providers

| Name | Version |
| ---- | ------- |
| aws | >= 6.36.0, < 7.0.0 |
| aws.management | >= 6.36.0, < 7.0.0 |

## Modules

No modules.

## Resources

| Name | Type |
| ---- | ---- |
| [aws_guardduty_organization_admin_account.this](https://registry.terraform.io/providers/hashicorp/aws/latest/docs/resources/guardduty_organization_admin_account) | resource |
| [aws_guardduty_organization_configuration.this](https://registry.terraform.io/providers/hashicorp/aws/latest/docs/resources/guardduty_organization_configuration) | resource |
| [aws_guardduty_organization_configuration_feature.this](https://registry.terraform.io/providers/hashicorp/aws/latest/docs/resources/guardduty_organization_configuration_feature) | resource |
| [aws_caller_identity.admin](https://registry.terraform.io/providers/hashicorp/aws/latest/docs/data-sources/caller_identity) | data source |

## Inputs

| Name | Description | Type | Default | Required |
| ---- | ----------- | ---- | ------- | :------: |
| detector\_id | ID of the GuardDuty detector in the delegated administrator account (`detector_id` output of the `guardduty` module). | `string` | n/a | yes |
| features | Features to auto-enable in member accounts, in the format of the `features` output of the `guardduty` module. | ```map(object({ enabled = bool additional_configuration = map(bool) }))``` | n/a | yes |
| auto\_enable\_organization\_members | Which member accounts GuardDuty is enabled for automatically: ALL (existing and new), NEW (only accounts joining later) or NONE. | `string` | `"ALL"` | no |
| region | AWS region to configure. Defaults to the region of the providers. GuardDuty organization settings are regional. | `string` | `null` | no |

## Outputs

| Name | Description |
| ---- | ----------- |
| admin\_account\_id | Account ID designated as the GuardDuty delegated administrator. |
| auto\_enable\_organization\_members | Auto-enable mode applied to member accounts. |
<!-- END_TF_DOCS -->
