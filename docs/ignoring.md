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

An ignore covers the findings about the element it is written on, and
nothing else:

| Written on | Covers |
|---|---|
| an operation | that operation's findings |
| a security scheme (`components.securitySchemes.x`) | that scheme's findings (PRC003) |
| a server (`servers[]`, at any level) | that server's findings (PRC004) |
| an OAuth2 flow (`flows.implicit`, ...) | that flow's findings (PRC011) |
| the spec's root | findings about the spec as a whole (PRC002 on the default `security`) |

An ignore on a security scheme also covers its OAuth2 flows. In a Swagger
2.0 spec, where servers are built from `schemes` and `host` and cannot carry
extensions, an ignore at the root also covers them (PRC004).

A schema shared by several operations (a `$ref` used by both `POST /admin/users`
and `POST /register`) is one finding, shown once where the field is written.
An ignore on one of those operations covers only that operation: the finding
is still reported for the others, under the first one not ignored.

So excusing one weak scheme never hides a second one added later.

```yaml
components:
  securitySchemes:
    basic:
      type: http
      scheme: basic
      x-procyon-ignore:
        - rule: PRC003
          reason: "Only the legacy importer uses it, behind the VPN"
```

`reason` is required. `expires` (a date) is optional: the ignore applies
until the end of that day, wherever Procyon runs; after it, its findings
count again and the report says it expired.

An ignored finding never fails the run, but it is listed under **Ignored**
with its reason in every format.

Ignores of runtime rules (PRC1xx, found by `procyon test`) are written the
same way, on the operation. `procyon lint` checks they are well formed but
never calls them unused, and `procyon test` does the same for lint rules.

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
