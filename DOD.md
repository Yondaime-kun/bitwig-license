# Definition of Done — bitwig-license

The six required items, each with the evidence rather than the claim.

## 1. PLAN.md with failure conditions written before the code

`PLAN.md` exists. It states three possible outcomes for this target — a
client-only check (generator possible), a weak server check (fake server
possible), or a server-held signing key (reader/verifier only) — and records that
which one applied was not known when it was written. It lists five failure
conditions, among them that the byte order of any length field must be read from
the client rather than assumed, because a wrong width parses successfully into a
shifted result instead of failing.

The outcome was case 3, and the plan was not edited to fit it afterwards.

## 2. RESEARCH.md

`RESEARCH.md` records the reversing: how the subsystem was located (grep on
`services.bitwig.com`, since class names are obfuscated and strings are not), the
live behaviour of the license service (405/415/200 with an octet-stream body),
the request framing from `clZ`, the nonce-keyed byte transform and MD5 handshake
from `cmF`/`cmD`/`cmE`, the four-block file layout from `cml`, the Ed25519
verification and the compiled-in public key, and the RSA-2048 + AES-128 payload
ciphering from `cmv`/`cmu`.

## 3. Working code

`internal/bitwig` (framing + verification), `cmd/bitwig-license` (CLI), 441 lines
non-test, zero dependencies.

```
BUILD_EXIT=0
VET_EXIT=0
gofmt -l internal cmd   -> (no output)
```

## 4. Tests actually executed

```
$ go test ./...
ok  	github.com/yondaime-kun/bitwig-license/internal/bitwig
TEST_EXIT=0

$ go test -race ./...
RACE_EXIT=0

15 tests, 0 failures.
```

Measured, not remembered: 15 top-level tests, 441 lines non-test, 279 lines test.

**Two real bugs were found by the tests during development, not after:**

- `Parse` read all four blocks with a uint16 length. The second block uses a
  uint32 length in the client (`cmH.hEW`). The test failed with
  `length prefix at 41 past end`; the fix was to separate `readShort` from
  `readInt` and use the latter for block 2. A dedicated test
  (`TestKeyBlockUses32BitLength`) now pins it with a 70,000-byte block, which
  cannot be mistaken for a 16-bit length.
- `buildFile` in the tests omitted the signature block, so the framing tests
  failed against a parser that was correct. The fix was in the test helper: real
  files always carry the block because `cml` reads it as the fourth block.

**Mutation testing: 5/5 caught.** Each was applied to `parse.go`, the suite run,
and the file restored:

| mutation | result |
| --- | --- |
| block 2 length read as uint32 -> uint16 | caught |
| uint16 length read big-endian | caught |
| magic check disabled | caught |
| signed length `-2` removed | caught |
| block bounds check removed | caught |

**Verification was shown to work in both directions.** A verifier that can only
return an error passes every negative test, so the mechanism was exercised with a
key under our control:

```
framing parse: OK (signed=93, sig=64)
verify with the signing key:   true    <- it can succeed
verify with the package key:   true (error, as required)  <- foreign key rejected
```

The CLI demonstrates the same thing: `synth` writes a correctly framed file,
`verify` rejects it because it is not Bitwig's key, and `explain` reports the
framing and `signed region = 117 = 183 - 64 - 2`, which is exactly the arithmetic
in the client.

## 5. Honest README

`README.md` states at the top what the tool is and what it is not, including that
it cannot generate a license and cannot decrypt the payload, with the reason
(private keys held by the server). The Limitations section records the real gap:
**no genuine `.activation` file was available**, so the format is verified against
files built to the reversed specification, not against a real license. That
distinction is stated rather than glossed.

## 6. Commit

See the repository history. One commit for the tool.

## Limits, carried forward

- No genuine license file was tested. Closing this needs a Bitwig license, which
  the work does not have.
- The payload schema is known from the reader in `cml` but has never been run
  against real decrypted bytes, because it cannot be decrypted here.
- The network protocol is documented, not implemented, for the same reason.
