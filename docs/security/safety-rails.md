# Rails

Global invariants:
- Only allowlisted file paths may be modified.
- Denylisted paths are always blocked.
- Resource deletions are blocked.
- Diff line budget is enforced.
- Common widening patterns are blocked, including public CIDRs, public accessibility, and obvious wildcard IAM policy fragments.

Notes:
- Safety is enforced via path allowlists, diff budget, no-deletion, and widening-pattern checks.
- Teams that want to disallow IAM mutations should enforce that via policy/allowlist path scoping and review policy.
- Rails are pattern-based safety checks, not a full semantic security analyzer.

Failure outcomes:
- `NOT_ALLOWLISTED`
- `BLOCKED_BY_RAIL`
