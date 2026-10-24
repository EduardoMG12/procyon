# Configuration

Procyon needs no configuration. Everything below is optional.

## Fail threshold

`--fail-on <severity>` sets the lowest severity that fails the run (exit code
`1`). Severities, from most to least serious: `critical`, `high`, `medium`,
`low`. The default is `high`.

```sh
procyon lint openapi.yaml --fail-on medium
```

## `.procyon.yaml`

An optional `.procyon.yaml` in the directory you run Procyon from sets the same
options for the whole team:

```yaml
fail-on: medium
ref-root: .
```

Flags always win over the file.

| Key | Flag | Meaning |
|---|---|---|
| `fail-on` | `--fail-on` | The lowest severity that fails the run |
| `ref-root` | `--ref-root` | A directory `$refs` may read anywhere under, instead of only the spec's own directory: for monorepos whose specs share files from a sibling folder. A relative path counts from the directory Procyon runs in. See [how `$refs` are read](refs.md). | An unknown key is an error, so a typo such as
`fail_on` never goes unnoticed.

The file holds **how** Procyon runs, never **what it ignores**. Ignores live in
the spec, on the operation they excuse, with a written reason, so the
exception sits next to what it describes and is reviewed with it.

## Exit codes

| Code | Meaning |
|---|---|
| `0` | No finding at or above the fail threshold |
| `1` | At least one finding at or above the fail threshold |
| `2` | Procyon could not run: bad arguments, unreadable or invalid spec, invalid `.procyon.yaml` |
