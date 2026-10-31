# vulnapi: a notes API that is vulnerable on purpose

The acceptance test of `procyon test` (v0.2, [PRD 0002](../../docs/prds/0002-v0.2-runtime-tests.md)).
Run against the vulnerable API, Procyon must report exactly the findings
below; run against the fixed twin (`-fixed`), none.

**Never run it anywhere but a test or a disposable container.**

## Accounts

Two seeded test accounts, by bearer token:

| Account | Token | Owns |
|---|---|---|
| A (alice) | `token-alice` | notes `1`, `2` |
| B (bob) | `token-bob` | note `3` |

`POST /login` with `{"username": "alice", "password": "alice-password"}`
(or bob's, `bob-password`) answers `{"session": {"token": "token-alice"}}`.

## Planted vulnerabilities

| Rule | Operation | Vulnerable API | Fixed twin |
|---|---|---|---|
| PRC101 | `GET /notes` | an anonymous caller gets every note | `401` |
| PRC102 | `GET /notes/{id}` | B reads A's note | `404` |
| PRC102 | `PUT /notes/{id}` | B changes A's note | `404` |
| PRC102 | `DELETE /notes/{id}` | B deletes A's note | `404` |
| PRC102 | `GET /owner-notes?owner=` | B lists A's notes by naming A in the query | `404` |
| PRC103 | `POST`, `PUT /notes…` | a body that is not a note (`{"title": 42}`) gives a `500` | `400` |
| PRC104 | `POST`, `PUT /notes…` | a missing `title`, or a `title` or `body` past its `maxLength`, is accepted | `400` |

Not vulnerable in either: `GET /health` and `POST /login` (public on purpose), `GET /me`, and
anonymous calls to every other operation (`401`).

`procyon lint openapi.yaml` reports two low findings (PRC008: `GET /notes`
and `GET /owner-notes` have no paging), and nothing about the vulnerabilities above. That is the
point: none of them shows in the spec.

## Running it

In tests, start it in-process: `httptest.NewServer(vulnapi.New(fixed))`.

As a container, from this directory:

```sh
docker compose up --wait          # the vulnerable API
FIXED=true docker compose up --wait   # the fixed twin
docker compose port api 8080      # the published port on 127.0.0.1
docker compose down -v
```

Or without Docker: `go run ./internal/vulnapi/cmd/vulnapi -addr 127.0.0.1:8080`.
