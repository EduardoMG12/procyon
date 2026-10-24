# How Procyon reads $refs

A spec can be split across files with `$ref: ./schemas/user.yaml`. Procyon
follows those references, and because a spec may come from anyone (a pull
request, a vendor, a public repository), it does so defensively.

## The rules

1. **Never the network.** A `$ref` to a URL (`https://`, `file://`, `//host`)
   is refused. Download the file and refer to it by a local path.
2. **One directory.** `$refs` read only from the spec's own directory, or,
   when you allow it, a directory that contains it (`RefRoot`, for monorepos
   whose specs share files from a sibling folder). `RefRoot` and the spec's
   path must be written the same way (both relative to the repository root,
   say), not through different links to the same place. That directory may
   never be the file system's root, your home directory, or a directory
   containing it, whatever name it is reached by.
3. **No hidden files.** `.git`, `.env`, `.aws` and every other name starting
   with `.` are never read, nor short 8.3 names (`GIT~1`, a tilde followed by
   a digit) that could alias them; `user~old.yaml` is fine. A spec that itself lives in a hidden directory (`.github/`) can
   still refer to files next to it.
4. **No symlinks.** Every part of a `$ref` path must be a plain directory or
   regular file; a symlink, a Windows junction, a FIFO or a device is
   refused.
5. **Limits.** At most 10 MiB per referenced file and 64 MiB for the spec
   itself. Every `$ref` counts against a 64 MiB total, even when it points at
   a file already read, because each reference is parsed again.
6. **The spec itself** must be a regular file: a symlink (to a device that
   never ends, or to a file outside the repository) is refused.

The path is checked as text before anything touches the file system, so a
`$ref` cannot probe the machine or learn whether a file exists outside the
directory. The file is then opened through Go's `os.Root`, and checked to
still be the file that was examined.

## Threat model

**Defended against:** a spec, and the files committed next to it, written
by an attacker, for example in a pull request linted by CI. They cannot make
Procyon read files outside the allowed directory, read hidden files inside
it, reach the network, or exhaust the runner's memory, and what they can
read is limited to files a reviewer can see in the pull request.

**Not defended against:** another process running on the same machine
during the lint, able to rename files and directories while Procyon reads
them. Such a process can already read the runner's files directly; Procyon
narrows the window (it re-checks the file after opening it) but does not
claim to close every race.

Found a way around these rules? Please report it privately: see
`SECURITY.md`.
