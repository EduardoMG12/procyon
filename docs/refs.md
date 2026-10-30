# How Procyon reads $refs

A spec can be split across files with `$ref: ./schemas/user.yaml`. Procyon
follows those references, and because a spec may come from anyone (a pull
request, a vendor, a public repository), it does so defensively.

## The rules

1. **Never the network.** A `$ref` to a URL (`https://`, `file://`, `//host`)
   is refused. Download the file and refer to it by a local path.
2. **One directory.** `$refs` read only from the spec's own directory, or,
   when you allow it, a directory that contains it (`--ref-root`, `ref-root`
   in `.procyon.yaml`, or `Options.RefRoot` in the library), for monorepos
   whose specs share files from a sibling folder. The root and the spec's
   path must be written the same way (both relative to the repository root,
   say), not through different links to the same place. That directory may
   never be the file system's root, your home directory, or a directory
   containing it, whatever name it is reached by.
3. **No hidden files.** `.git`, `.env`, `.aws` and every other name starting
   with `.` are never read, nor 8.3 short names (`GIT~1`, `PROGRA~2.EXE`)
   that could alias them; `user~old.yaml` and `order~2024.yaml` are fine. A spec that itself lives in a hidden directory (`.github/`) can
   still refer to files next to it.
4. **No symlinks.** Every part of a `$ref` path must be a plain directory or
   regular file; a symlink, a Windows junction, a FIFO or a device is
   refused.
5. **Limits.** At most 16 MiB for the spec, 10 MiB per referenced file,
   32 MiB read from disk through all `$refs`, 16 MiB parsed again through
   all `$refs`, and 20,000 `$refs` resolved. A file is read once but may be
   parsed many times: again for each `$ref` to the whole file
   (`./error.yaml`), and, for each `$ref` into an `x-` extension of a header
   and similar places the parser cannot reach directly, the file the `$ref`
   sits in. A `$ref` into a file (`./common.yaml#/User`) parses it only the
   first time.
6. **The spec itself** must be a regular file, not a symlink (to a device
   that never ends, or to a file outside the repository), and not reached
   through a directory symlink leading outside the working directory.

The path is checked as text before anything touches the file system, so a
`$ref` cannot probe the machine or learn whether a file exists outside the
directory. The file is then opened through Go's `os.Root`, and checked to
still be the file that was examined.

## Threat model

**Defended against:** a spec, and the files committed next to it, written
by an attacker, for example in a pull request linted by CI. They cannot make
Procyon read outside the allowed directory, read hidden files, follow
symlinks, reach the network, or read unbounded amounts of data.

**Not defended against:**

- **Files that are in the allowed directory but not in the repository.**
  Procyon does not know which files git tracks. If an earlier CI step writes
  something sensitive into the workspace without a leading dot (some cloud
  login actions write credential files such as `gha-creds-*.json`), a spec
  that guesses its name can make Procyon read it, and parts of it may show
  up in error messages. **Run Procyon before any step that writes secrets
  into the workspace**, or give it a directory that holds only the specs.
- **Expensive parsing within the limits.** Parsing can use far more memory
  than a file's size; a spec built to be expensive can still slow a run or
  exhaust a small runner. The limits bound the damage, not the cost.
- **Another process on the same machine** renaming files while Procyon reads
  them. Such a process can already read the runner's files directly;
  Procyon re-checks each file after opening it but does not claim to close
  every race.

**Also refused, deliberately:** a spec directly in your home directory
(including containers where `HOME` is the project directory, such as
`HOME=/app`): `$refs` from it would expose everything in home. Move the
specs into a subdirectory.

Found a way around these rules? Please report it privately: see
`SECURITY.md`.
