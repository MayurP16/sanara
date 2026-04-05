# Terraform Validation

Sanara can validate a proposed Terraform fix before it opens a remediation PR.

This matters because Sanara is not just editing `.tf` files. It tries to prove that the repo can still pass Terraform checks after the change.

## What Sanara runs

Before creating a remediation PR, Sanara runs:

- `terraform fmt` — always applied; changes are committed with the fix
- `terraform init -backend=false`
- `terraform validate`
- `terraform plan -refresh=false` — only when `plan_required: true`

## How the gate works

Sanara runs Terraform checks **twice**: once before applying any fixes (the baseline) and once after. It compares the two results.

- If a Terraform run was **already failing before** Sanara's fix and fails the **same way after** — the pre-existing failure is noted in the PR body but does **not** block the PR.
- If a Terraform run was **passing before** but **fails after** — that is a regression introduced by Sanara. The PR is blocked and no changes are published.
- If a Terraform run was **already failing before** but fails **differently after** — that also counts as a regression introduced by Sanara.
- If Terraform passes both before and after — normal path, PR is created.

Comparison is done per runnable Terraform root, not as a single repo-wide pass/fail bit.

This means repositories with one pre-existing broken example or harness can still receive Sanara remediation PRs, while new failures introduced in other examples or modules still block publish correctly.

The baseline result is written to `terraform/baseline_checks.json` in the artifact bundle.

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

If `plan_required: true` and no runnable setup is found at all, Sanara will not create a remediation PR (`missing_harness`).

## The simple rule for users

For most repositories Sanara will automatically fall back to the workspace root, so you may not need any extra configuration.

If your Terraform setup is more complex — multiple modules, non-root working directories, specific var files — give it one of these:

- runnable Terraform under `examples/**`, or
- a `.sanara/harness.yml` file that tells it how to run Terraform

If you want to start without any validation gates:

- `publish_dry_run: true` during rollout — validates locally but does not open PRs
- `plan_required: false` — skips the plan gate entirely; useful for early adoption but removes an important safety check

## If you want to stop validating `examples/**`

Use `.sanara/harness.yml` when you want to control **Terraform validation scope**.

For example, to validate only the repository root and ignore `examples/**` for Terraform `init` / `validate` / `plan`:

```yaml
version: 1
runs:
  - name: root
    working_dir: .
    init:
      backend: false
    plan:
      refresh: false
```

Important:

- `.sanara/harness.yml` changes Terraform validation behavior
- it does **not** change what Checkov scans
- to change scan/remediation/blocking behavior, use `.sanara/policy.yml`

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
