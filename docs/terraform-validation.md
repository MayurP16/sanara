# Terraform Validation

Sanara can validate a proposed Terraform fix before it opens a remediation PR.

This matters because Sanara is not just editing `.tf` files. It tries to prove that the repo can still pass Terraform checks after the change.

## What Sanara runs

Before creating a remediation PR, Sanara can run:

- `terraform fmt`
- `terraform init -backend=false`
- `terraform validate`
- `terraform plan -refresh=false`

## Why this is needed

Terraform usually has to run from a specific directory, with the right variables and settings.

Sanara needs a clear way to know:

- where Terraform should run
- whether backend access should be disabled
- whether extra var files or environment variables are needed

That setup is what this document used to call the "harness".

## How Sanara finds a runnable Terraform setup

Sanara looks for Terraform validation in this order:

1. If `examples/**` exists, each example directory is treated as a runnable Terraform root.
2. Otherwise, if `.sanara/harness.yml` exists, Sanara uses the runs defined there.
3. Otherwise, Sanara cannot run Terraform validation.

If Terraform validation is required and no runnable setup exists, Sanara will not create a remediation PR.

## The simple rule for users

If you want Sanara to open remediation PRs safely, give it one of these:

- runnable Terraform under `examples/**`, or
- a `.sanara/harness.yml` file that tells it how to run Terraform

If you do not have that yet, you can still start with:

- `publish_dry_run: true` during rollout, or
- `plan_required: false` if you intentionally want weaker validation

`plan_required: false` is useful for early adoption, but it removes an important safety check.

## Example `.sanara/harness.yml`

```yaml
version: 1
runs:
  - name: app
    working_dir: .
    init:
      backend: false
    plan:
      refresh: false
```

## Optional fields

Each run can also include:

- `timeout_seconds`
- `env`
- `var_files`

Use these only if your Terraform setup needs them.
