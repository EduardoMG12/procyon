# Benchmark: APIs vulnerable on purpose

What Procyon v0.1 finds in the specs of APIs built to be insecure, against
the vulnerabilities their authors document. It shows what a spec linter can
and cannot see, and what is left for runtime tests (v0.2).

The specs are in [`testdata/corpus/`](../testdata/corpus/). Every hit below is
pinned in [`expected.txt`](../testdata/corpus/expected.txt), so a change that
loses one fails `TestKnownBadSpecs`.

Legend: **✓** found from the spec · **~** related finding, not the whole
problem · **✗ v0.2** needs the running API · **✗ spec** not visible in the spec.

## crAPI (OWASP)

| Challenge | Result | Finding |
|---|---|---|
| 1, 2. Another user's vehicle / mechanic report (BOLA) | ✗ v0.2 | Authenticated, so nothing in the spec says the server skips the owner check |
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

| Vulnerability | Result | Finding |
|---|---|---|
| SQL injection | ✗ v0.2 | |
| Unauthorized password change | ✗ v0.2 | Authenticated; the missing owner check is in the code |
| BOLA on books | ~ | PRC005: the book's `secret` is in the response |
| Mass assignment (`admin` at sign-up) | ✗ spec | The field is not in the spec |
| Excessive data exposure through the debug endpoint | ✓ | PRC005 (`password`), PRC006 (`email`), PRC001 |
| User and password enumeration | ~ | PRC007, PRC006 on `GET /users/v1/{username}` (usernames); different login error messages are runtime |
| RegexDOS | ✗ v0.2 | |
| Lack of rate limiting | ✗ | Out of scope (no spec field for it) |
| JWT with a weak signing key | ✗ v0.2 | |

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
