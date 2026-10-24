# Ignoring a finding

Sometimes a finding is fine on purpose. Procyon lets you say so, but never
silently: every exception lives in the spec, next to what it excuses, with a
written reason, and it keeps showing up in every report.

## Public operations

An operation that is meant to be reachable without authentication (a health
check, the login operation itself) is marked once:

```yaml
/health:
  get:
    x-procyon-public: "Load balancer health check, returns no data"
```

This silences **PRC001 only**. Rules about what a public operation exposes
(personal data, PRC006; objects by ID, PRC007) still apply: being public is
exactly what makes those dangerous.

## x-procyon-ignore

Any finding can be ignored, one rule at a time:

```yaml
/reports/{id}:
  get:
    x-procyon-ignore:
      - rule: PRC007
        reason: "Report IDs are random UUIDs"
      - rule: PRC001
        reason: "Public until the auth migration"
        expires: 2027-01-31
```

- **On an operation**, it covers that operation's findings.
- **At the spec's root**, it covers findings about no operation: a security
  scheme (PRC003), a server (PRC004), an OAuth2 flow (PRC011).
- `reason` is required. `expires` (a date) is optional: after that day the
  ignore stops applying, its findings count again, and the report says it
  expired.

An ignored finding never fails the run, but it is listed under **Ignored**
with its reason in every format.

## Mistakes are errors

A missing reason, an unknown rule ID (`PRC01`), a date that is not a date,
or an unknown key stops the run (exit code `2`) and points at the
`x-procyon-ignore` key. A typo must never ignore something by accident.

An ignore that matches nothing is reported under **Notes**, so dead ignores
get cleaned up. Notes never fail the run.

## Not in .procyon.yaml

`.procyon.yaml` sets how Procyon runs (`fail-on`), never what it ignores.
An exception belongs next to what it excuses, where reviewers of that part
of the spec see it.
