# Benchmark: APIs vulnerable on purpose

What Procyon finds in APIs built to be insecure, against the
vulnerabilities their authors document: `procyon lint` (v0.1) from their
specs, and, for VAmPI so far, `procyon test` (v0.2) against the running API.
It shows what a spec linter can and cannot see, and what runtime tests add.

The specs are in [`testdata/corpus/`](../testdata/corpus/). Every hit below is
pinned in [`expected.txt`](../testdata/corpus/expected.txt), so a change that
loses one fails `TestKnownBadSpecs`.

Legend: **✓** found from the spec · **~** related finding, not the whole
problem · **✗ v0.2** needs the running API · **✗ spec** not visible in the spec.

## crAPI (OWASP)

`procyon test` also runs against crAPI's public images every week
([benchmark.yml](../.github/workflows/benchmark.yml), with
[this setup](../testdata/benchmark/crapi/)). The test accounts start with
nothing of their own; each creates a post, an order and a product first.
It finds that **another account reads A's vehicle location** (challenge 1;
PRC102 on `GET /identity/api/v2/vehicle/{vehicleId}/location`), that **an
anonymous caller and another account both read A's order, with A's email
and phone** (PRC101 and PRC102 on `GET
/workshop/api/shop/orders/{order_id}`), and that several bodies the spec
forbids are accepted (PRC104). The setup gives each account its vehicle
with the code crAPI e-mails it, and declares A's vehicle ID: crAPI calls
it `uuid` in its list, which the spec does not tie to `{vehicleId}`.

| Challenge | Result | Finding |
|---|---|---|
| 1, 2. Another user's vehicle / mechanic report (BOLA) | ✗ lint · ✓ test (1) | Lint: authenticated, so nothing in the spec says the server skips the owner check. Test: PRC102, B reads A's vehicle location |
| 3. Reset another user's password (OTP brute force) | ~ | PRC001 on the OTP checks, which are meant to be public; the missing rate limit is runtime |
| 4, 5. Other users' data, internal video property | ✗ spec | Returned to logged-in users; the fields look ordinary |
| 6. Layer 7 DoS through contact_mechanic | ✓ | PRC008: `number_of_repeats` has no maximum |
| 7. Delete another user's video | ✓ | PRC010: an admin path with regular users' authentication |
| 8, 9. Free item, more balance (mass assignment) | ✗ v0.2 | `quantity` and `status` are accepted by the server, not by the spec |
| 10. Update internal video properties | ✗ spec | `conversion_params` is writable; nothing marks it internal |
| 11. SSRF | ✗ v0.2 | `mechanic_api` is a URL the server calls; a URL field alone is not a finding |
| 12, 13. NoSQL and SQL injection | ✗ v0.2 | |
| 14. Endpoint without authentication | ~ | PRC001 on `receive_report` and `return_qr_code`, which declare no security. The endpoint the challenge means (an order by ID) is declared authenticated in the spec; only its code skips the check |
| 15. Forged JWT | ✗ v0.2 | |
| 16–18. Chatbot | ✗ | Out of scope |

Also found: PRC010 on `GET /workshop/api/management/users/all`, and paging
`limit`s without a maximum (PRC008).

## VAmPI

`procyon test` runs against VAmPI's public image (`vulnerable=1`) every
week ([benchmark.yml](../.github/workflows/benchmark.yml), with
[this config](../testdata/benchmark/vampi/)), and fails if a vulnerability
found below is lost.

| Vulnerability | `lint` | `test` | Finding |
|---|---|---|---|
| SQL injection | ✗ | ✗ | Injection is out of scope for v0.2 |
| Unauthorized password change | ✗ | ~ | `test`: a note, not a finding. B's change returns 204, but no read shows a password, so Procyon cannot confirm it |
| BOLA on books | ~ | ✓ | `lint`: PRC005, the book's `secret` is in the response. `test`: PRC102, B reads A's book secret |
| Mass assignment (`admin` at sign-up) | ✗ | ✗ | The field is not in the spec, so nothing sends it |
| Excessive data exposure through the debug endpoint | ✓ | – | PRC005 (`password`), PRC006 (`email`), PRC001 |
| User and password enumeration | ~ | ✗ | `lint`: PRC007, PRC006 on `GET /users/v1/{username}`; different login error messages are not compared |
| RegexDOS | ✗ | ✓ | `test`: PRC103, a 100 000-character email gets no answer within the timeout |
| Lack of rate limiting | ✗ | ✗ | Out of scope |
| JWT with a weak signing key | ✗ | ✗ | Out of scope for v0.2 |

`test` also reports PRC104 on `POST /users/v1/register`, `POST
/users/v1/login` and `POST /books/v1`: VAmPI accepts bodies its spec
forbids. Running it changed four oracles (PRD 0002, *Discoveries*).

## Pixi (OWASP DevSlop)

A Swagger 2.0 spec in one minified line; its credential is a header
parameter, not a security scheme (PRC001 counts it as authentication).
Pixi lists its challenges in `app/ctf.html`, not in its README.

| Vulnerability | Result | Finding |
|---|---|---|
| Mass assignment: make yourself admin, give yourself money | ✓ | PRC009 on `is_admin` in `UsersItem`, the body of register, login, `edit_info` and admin money. It is reported once, under the first of them (`POST /api/admin/money`); the real holes are register and `edit_info` |
| Admin operations open to any user | ✓ | PRC010 on the four `/api/admin/` operations: they take the same token as every user operation. Pixi's code agrees (its admin handlers only check the token), although its spec's admin paths differ from the code's |
| Injection in the admin API, deleting or changing other users' photos and profiles | ✗ v0.2 | |

Also found: PRC001 on `PUT /api/user/edit_info`, whose spec leaves out the
token every other user operation declares (Pixi's server does check it: a
gap in the spec, not in the API), and PRC004 (the spec's server is plain
HTTP).

## Juice Shop (OWASP), B2B order API

| Vulnerability | Result | Finding |
|---|---|---|
| RCE / DoS through `orderLinesData` | ~ | PRC008: an unbounded string the server evaluates |
| The rest of Juice Shop | ✗ spec | Only the B2B order API has a spec |

## Not in the corpus

**dvws-node** is GPL-3.0, which this Apache-2.0 repository cannot include.
Its OpenAPI 3 spec is also invalid (`in: body` parameters, a Swagger 2.0
construct), so Procyon refuses it with an input error (exit 2).

## What this says about v0.2

Most vulnerabilities above are about what the server **does** with a valid
request: whose object it returns, what it copies into the record, what it
runs. A spec cannot show that. v0.2 tests a disposable running copy of the
API, and these APIs are its benchmark.
