# Procyon

**Automatic security QA for your API.** Procyon reads your OpenAPI spec and
tells you, in plain words, where your API's design leaves a door open:
operations without authentication, secrets in responses, personal data
exposed to anonymous callers, clients that can make themselves admin. It runs
in CI and fails the build before the problem ships, without you writing a
single test.

> **Status: planning.** Nothing is released yet. The plan lives in
> [docs/prds/](docs/prds/): start with the [vision](docs/prds/0000-vision.md)
> and the [v0.1 PRD](docs/prds/0001-v0.1-spec-lint.md).

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

## What it will look like (v0.1)

```sh
procyon lint openapi.yaml
```

```text
high  PRC001  Operation has no authentication
      openapi.yaml:42:5  GET /users/{id}

      40 |   /users/{id}:
      41 |     get:
    > 42 |       operationId: getUser
      43 |       responses:

      Why: anyone who knows the URL can call this operation.
      Fix: add a security requirement, or mark it public on purpose with
           x-procyon-public: "<reason>".
      More: docs/rules/PRC001.md

1 high · 0 medium · 0 low · 0 ignored   (fails at: high)
```

Formats: `terminal`, `json`, `sarif` (GitHub code scanning) and `markdown`
(job summaries). Inputs: OpenAPI 3.0, 3.1 and Swagger 2.0, YAML or JSON.

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
