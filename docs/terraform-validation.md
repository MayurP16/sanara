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

Sanara looks for a runnable Terraform setup in this order:

1. **`examples/`** — if this directory exists, each subdirectory is treated as a runnable Terraform root.
2. **`.sanara/harness.yml`** — if present, Sanara uses the runs defined there.
3. **Workspace root (`inferred_root`)** — if neither of the above exists, Sanara falls back to running Terraform from the repository root.

If `plan_required: true` and none of the above produce a successful run, Sanara will not create a remediation PR.

## The simple rule for users

For most repositories Sanara will automatically fall back to the workspace root, so you may not need any extra configuration.

If your Terraform setup is more complex — multiple modules, non-root working directories, specific var files — give it one of these:

- runnable Terraform under `examples/**`, or
- a `.sanara/harness.yml` file that tells it how to run Terraform

If you want to start without any validation gates:

- `publish_dry_run: true` during rollout — validates locally but does not open PRs
- `plan_required: false` — skips the plan gate entirely; useful for early adoption but removes an important safety check

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
