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
format: terminal
output:
  - sarif=procyon.sarif
  - markdown=summary.md
```

Flags always win over the file. One `--output` flag replaces the file's whole
`output` list, so a local run never writes files you did not ask for.

| Key | Flag | Meaning |
|---|---|---|
| `fail-on` | `--fail-on` | The lowest severity that fails the run |
| `ref-root` | `--ref-root` | A directory `$refs` may read anywhere under, instead of only the spec's own directory: for monorepos whose specs share files from a sibling folder. A relative path counts from the directory Procyon runs in. See [how `$refs` are read](refs.md). |
| `format` | `--format` | What to print: `terminal` (default), `json`, `sarif` or `markdown` |
| `output` | `--output` | A list of `format=path`: other formats to write to files |
| `test.accounts.a.login`, `test.accounts.b.login` | | For `procyon test`: how test account A or B logs in, when `PROCYON_USER_A_TOKEN` / `PROCYON_USER_B_TOKEN` is not set. `operation` (`POST /login`, as in the spec), `body` (sent as JSON; `${PROCYON_…}` reads an environment variable, so no password is written in the file; only names starting with `PROCYON_` can be read, so a changed config cannot send CI's other secrets to the target) and `token` (a JSON pointer to the token in the response, such as `/token` or `/session/token`) |
| `test.skip` | | For `procyon test`: operations never called, by anyone (`["GET /createdb"]`): a "read" that resets the database would spoil the run |
| `test.ids` | | For `procyon test`: values of test account A's objects by path or query parameter name (`orderId: ["42"]`): used when A's responses show none, or none Procyon can tell is A's |

```yaml
test:
  accounts:
    a:
      login:
        operation: POST /login
        body: {username: alice, password: "${PROCYON_A_PASSWORD}"}
        token: /session/token
    b:
      login:
        operation: POST /login
        body: {username: bob, password: "${PROCYON_B_PASSWORD}"}
        token: /session/token
```

An unknown key is an error, so a typo such as `fail_on` never goes unnoticed.

The file holds **how** Procyon runs, never **what it ignores**. Ignores live in
the spec, on the operation they excuse, with a written reason, so the
exception sits next to what it describes and is reviewed with it.

## Exit codes

| Code | Meaning |
|---|---|
| `0` | No finding at or above the fail threshold |
| `1` | At least one finding at or above the fail threshold |
| `2` | Procyon could not run: bad arguments, unreadable or invalid spec, invalid `.procyon.yaml` |
