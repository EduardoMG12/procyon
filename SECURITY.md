# Security

Procyon reads specs that may come from anyone (a pull request, a vendor, a
public repository), so a bug in how it reads them can matter.

## Reporting a problem

**Do not open a public issue.** Report it privately through GitHub:
*Security → Report a vulnerability* in this repository
(<https://github.com/EduardoMG12/procyon/security/advisories/new>).

Please include the spec (or a minimal version of it) that triggers the
problem, what Procyon did, and what you expected. You will get an answer
within a week; fixes for confirmed problems come before any new feature.

A rule that misses a problem it should catch (a false negative) is not a
security problem in Procyon: open a normal issue with the
*False negative or false positive* template.

## What Procyon promises

- `procyon lint` never makes network requests. Remote `$ref`s are refused.
- It only reads the spec file and the local files the spec references.
- A malformed or hostile spec produces an error, never a crash.

## Supported versions

Only the latest release gets security fixes.
