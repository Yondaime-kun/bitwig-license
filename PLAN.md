# bitwig-license — plan

## What this is

A reader and verifier for **Bitwig Studio license files**, built from the
reversed client. Not a crack, and not a fake server: the aim is a tool that takes
a `.activation` file and says what it is and whether its signature holds, offline,
using only the public material the client itself carries.

## Why this target

Bitwig Studio is a commercial DAW ($99–399) whose entitlement is decided by a
server. Measured before committing to it:

| check | result |
| --- | --- |
| `bitwig+crack` on GitHub | 0 repositories |
| `bitwig+keygen` | 0 |
| `bitwig+license` | 0 |
| `bitwig+offline+activation` | 0 |
| what does exist | content-generation and MCP tools, no bypass |
| binary | `bitwig-studio-5.3.5.deb`, 341 MB, downloadable |
| implementation language | Java — `bin/bitwig.jar`, 28,936 classes, decompilable |

A premium, widely used application with no public bypass, whose license logic is
**readable as source** rather than only disassemblable.

## What was expected to be built

Three outcomes were possible, and which one applied was not known when this plan
was written:

1. **The license is client-verified only.** Then a generator is possible: sign
   files the client accepts. This was the hoped-for case.
2. **The license is server-issued, but the check is weak.** Then a fake server
   plus a signature replay might work.
3. **The license is signed with a key the client does not hold.** Then no
   generator is possible from the client alone, and the honest deliverable is a
   reader and verifier.

**Which one it turned out to be is recorded in RESEARCH.md, and it is 3.** The
plan is kept as written so the outcome can be judged against what was expected,
not adjusted to fit it afterwards.

## Failure conditions

Written before the code, so a bad result is recognisable as one:

- **If the file's framing cannot be read without a key**, the whole approach is
  wrong: the format would be opaque and this becomes guesswork. Stop.
- **If the signature cannot be checked with a public key from the client**, then
  case 3 does not hold and the deliverable changes; do not ship a "verifier"
  that cannot verify.
- **If verification cannot be shown to both accept and reject** — accepting a
  genuine signature and rejecting an altered one — then no verification has been
  demonstrated and the tool must not claim to verify. A verifier that only ever
  returns errors is decoration.
- **If a single altered byte does not invalidate the signature**, the check is
  not over the whole file and the model of the format is wrong.
- **If the byte order of any length field is assumed rather than read from the
  client**, structural bugs will parse successfully and shift later offsets. The
  lengths must be taken from the client's own reader.

## Definition of done

The six portfolio items: `PLAN.md`, `RESEARCH.md`, working code, tests actually
run, an honest `README.md`, and a commit. Plus `DOD.md` recording evidence.

## Scope, stated plainly

In scope: the file framing, the signature check, and the recovered public
material.

Out of scope, and not to be implied: decrypting the payload. Its content key is
RSA-wrapped with a private key held by Bitwig's server. Anything that claimed to
"read the license contents" would be claiming to break RSA-2048.
