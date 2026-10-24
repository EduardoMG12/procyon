# Procyon

**Automatic security QA for your API.** Procyon reads your OpenAPI spec and
tells you, in plain words, where your API's design leaves a door open:
operations without authentication, secrets in responses, personal data
exposed to anonymous callers, clients that can make themselves admin. It runs
in CI and fails the build before the problem ships, without you writing a
single test.

> **Status: v0.1 in development.** Everything below works from source; no
> release is published yet.

## Why

Your tests check that the API does what it should. Procyon checks that it
can't be misused. The expectations are the same for every API, so Procyon
knows them already:

- every operation requires authentication, unless it is public on purpose;
- one user can't reach another user's objects;
- passwords, tokens and secrets never appear in responses;
- clients can't write fields like `role` or `isAdmin`.

It works for an API written in any language: Procyon reads the spec, never
your source code.

## Usage

The repository is private for now, so build from a clone:

```sh
go install ./cmd/procyon
procyon lint openapi.yaml
```

```text
HIGH    PRC001  Operation has no authentication
        openapi.yaml:7:5  GET /orders

          5 | paths:
          6 |   /orders:
        > 7 |     get:
          8 |       operationId: listOrders
          9 |       responses:

        Why:  Anyone who can reach the API can call this operation, without
              proving who they are.
        Fix:  Add a security requirement to the operation or to the whole spec.
        More: https://github.com/EduardoMG12/procyon/blob/main/docs/rules/PRC001.md

FAILED  1 high · 0 medium · 0 low · 0 ignored  (fails at: high)
```

Exit code `0` passed, `1` a finding at or above the fail threshold, `2`
Procyon could not run. Inputs: OpenAPI 3.0 and 3.1, YAML or JSON, split
across local files or not (Swagger 2.0 is not supported yet).

| Flag | |
|---|---|
| `--fail-on <severity>` | `critical`, `high` (default), `medium` or `low` |
| `--format <format>` | what to print: `terminal` (default), `json`, `sarif`, `markdown` |
| `--output <format>=<path>` | also write a format to a file; repeatable |
| `--ref-root <dir>` | let `$refs` read anywhere under `dir` (monorepos) |

`fail-on` and `ref-root` can also live in a `.procyon.yaml`. See
[configuration](docs/configuration.md), [ignoring a finding](docs/ignoring.md),
[how `$refs` are read](docs/refs.md) and the [JSON format](docs/json-format.md).

### In GitHub Actions

Until binaries are published, install from a checkout of this repository:

```yaml
- uses: actions/checkout@v5
  with:
    repository: EduardoMG12/procyon
    path: procyon
- run: cd procyon && go install ./cmd/procyon
- run: procyon lint openapi.yaml --output sarif=procyon.sarif --output markdown=$GITHUB_STEP_SUMMARY
- uses: github/codeql-action/upload-sarif@v3
  if: always()
  with:
    sarif_file: procyon.sarif
```

Run Procyon before any step that writes credentials into the workspace
(see [docs/refs.md](docs/refs.md)).

## Rules

| ID | Severity | Catches |
|---|---|---|
| [PRC001](docs/rules/PRC001.md) | high | Operation has no authentication |
| [PRC002](docs/rules/PRC002.md) | high | Security requirement names an undefined scheme |
| [PRC003](docs/rules/PRC003.md) | medium | API key in the query string, or HTTP Basic |
| [PRC004](docs/rules/PRC004.md) | high | Server URL without TLS |
| [PRC005](docs/rules/PRC005.md) | high | Secret returned in a response |
| [PRC006](docs/rules/PRC006.md) | high | Personal data returned without authentication |
| [PRC007](docs/rules/PRC007.md) | high | Object addressed by ID without authentication |
| [PRC008](docs/rules/PRC008.md) | low | Unbounded input or unpaged list |
| [PRC009](docs/rules/PRC009.md) | medium | Client can write a privileged field (mass assignment) |
| [PRC010](docs/rules/PRC010.md) | medium | Admin operation protected like regular ones |
| [PRC011](docs/rules/PRC011.md) | medium | Deprecated OAuth2 flow |

## Roadmap

| Version | What it does |
|---|---|
| **v0.1 — Lint** | Reads the spec and reports security problems in the API's design. |
| **v0.2 — Runtime tests** | Starts a disposable copy of your API with test accounts, checks that one user can't reach another's data, then tears it down. Never touches production. |
| **v0.3 — Security QA environment** | Runs continuously against a permanent security-QA environment, with history. |

## Use it responsibly

Procyon is a defensive tool. Run it only on APIs you own or are authorized to
test.

## Contributing

Read [CONTRIBUTING.md](CONTRIBUTING.md). Security problems in Procyon itself:
[SECURITY.md](SECURITY.md).

## License

[Apache-2.0](LICENSE).
