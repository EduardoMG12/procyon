# JSON format

`procyon lint --format json spec.yaml` prints the whole report as JSON, and
`--output json=report.json` writes it to a file alongside the terminal
output. The exit code is the same whatever the format.

## Stability

`version` is the shape's version. Fields are only ever **added** within a
version; removing or renaming one bumps it. Scripts should check
`version == 1` and ignore fields they do not know.

## Shape (version 1)

```json
{
  "version": 1,
  "failed": true,
  "failOn": "high",
  "summary": { "critical": 0, "high": 1, "medium": 0, "low": 0, "ignored": 1 },
  "findings": [
    {
      "rule": {
        "id": "PRC001",
        "title": "Operation has no authentication",
        "severity": "high",
        "owasp": "API2:2023 Broken Authentication",
        "docs": "https://github.com/EduardoMG12/procyon/blob/main/docs/rules/PRC001.md"
      },
      "location": { "file": "specs/shop.yaml", "line": 9, "column": 5 },
      "operation": "GET /orders",
      "why": "Anyone who can reach the API can call this operation, ...",
      "fix": "Add a security requirement to the operation or to the whole spec."
    }
  ],
  "ignored": [
    { "rule": { "...": "..." }, "location": { "...": "..." },
      "why": "...", "fix": "...", "reason": "Internal mirror", "expires": "2027-01-31" }
  ],
  "notes": [
    { "location": { "file": "specs/shop.yaml", "line": 27, "column": 7 },
      "message": "ignore of PRC010 on GET /orders matches no finding; remove it" }
  ]
}
```

| Field | Meaning |
|---|---|
| `failed` | `true` when a finding is at or above `failOn`; then the exit code is `1` |
| `failOn` | The fail threshold used: `critical`, `high`, `medium` or `low` |
| `summary` | Findings per severity, and how many were ignored |
| `findings` | What is wrong, most serious first is **not** guaranteed: they are in file, line, column order |
| `findings[].operation` | `"GET /orders"`; absent for findings about no operation (a scheme, a server) |
| `ignored` | Findings an `x-procyon-ignore` matched, with its `reason` and optional `expires` |
| `notes` | Expired or unused ignores; they never fail the run |

`file` always uses forward slashes, on every system. `findings`, `ignored`
and `notes` are always arrays, empty rather than missing.
