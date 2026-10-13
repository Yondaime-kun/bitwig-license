# bitwig-license

Read and verify **Bitwig Studio** license files (`.activation`) offline.

```
bitwig-license explain <file>   # what the file is, block by block
bitwig-license verify  <file>   # does the Ed25519 signature hold?
bitwig-license keys             # the public material recovered from the client
bitwig-license synth  <file>    # write a sample file in the real framing
```

## What this is, and what it is not

**It is** a reader for the license file format and a check of its signature using
the public key compiled into the client. Both work offline on a real
`.activation` file.

**It is not** a license generator. Bitwig license files are **Ed25519-signed with
a private key Bitwig holds**, and the payload is **AES-128-encrypted under a key
wrapped with RSA-2048**, private half also on the server. Nothing in the client
can produce either. That is stated plainly because the tool would be dishonest if
it left you guessing — see [RESEARCH.md](RESEARCH.md) for the code that proves it.

This package had three possible outcomes; it turned out to be the third, and
[PLAN.md](PLAN.md) records the expectation as it was written *before* the code so
the result can be judged against it rather than fitted to it afterwards.

## Install and run

Go 1.24 or newer, no third-party dependencies.

```
go build ./cmd/bitwig-license
```

Or run the full check and demo:

```
./run.sh
```

## Usage

```
$ ./bitwig-license keys
Ed25519 public key (raw, 32 bytes)
  hex    d6efd7601ce345e38afbd9e40b8edf14754c79a386e4920a8ec425b2ad6542f8
  base64 1u/XYBzjReOK+9nkC47fFHVMeaOG5JIKjsQlsq1lQvg=

RSA public key (unwraps the content key)
  modulus  256 bytes (2048 bits)
  exponent 65537
```

```
$ ./bitwig-license explain sample.activation
file      sample.activation
size      183 bytes
magic     ff ef df  (cml.GS)

blocks, in the order cml reads them:
  material   offset      5      16 bytes   uint16 length prefix
  key        offset     25      46 bytes   uint32 length prefix
  payload    offset     73      44 bytes   uint16 length prefix
  signature  offset    119      64 bytes   uint16 length prefix

signed region: first 117 bytes (file length minus the signature block and its prefix)
signature valid under the recovered Bitwig key: no
```

```
$ ./bitwig-license verify some.activation
INVALID  license signature did not verify
```

`synth` writes a file framed exactly as a real one but signed with a key of its
own, so `verify` rejects it. That is the point: it exercises the framing and the
signature mechanism without pretending to produce a license Bitwig would accept.

## The file format

Reversed from `bitwig.jar` (Bitwig Studio 5.3.5), class `cml`:

```
[cml.GS magic: ff ef df]
[material]   uint16 little-endian length, then bytes
[key]        uint32 little-endian length, then bytes   <- the odd one out
[payload]    uint16 little-endian length, then bytes
[signature]  uint16 little-endian length, then 64 bytes
```

The signature is **Ed25519** over everything from the start of the file up to the
signature block's own 2-byte length prefix — i.e. `len - sigLen - 2`, which is the
expression the client uses.

Block 2 uses a 32-bit length while the others use 16 — that is not a typo, it is
what `cml` does (`cmH.hEW` for block 2, `cmH.MYk` for the rest). Reading it as
16-bit shifts every following offset and still parses, so the widths were taken
from the client's own reader rather than assumed. There is a test for it
specifically (`TestKeyBlockUses32BitLength`).

## The recovered keys

Compiled into the client, so public by construction — the client must carry them
to verify:

- **Ed25519 public key**, from `cml.GS()`, decoded from an X.509 SPKI blob.
- **RSA-2048 modulus and e=65537**, from `cmv`, which unwraps the content key.

These are in [internal/bitwig/keys.go](internal/bitwig/keys.go), each with the
decompiled source it came from.

## Tests

```
go test ./...
```

15 tests. They cover framing, byte order for both length widths, block bounds,
signature verification in both directions (a signature that must verify, and
altered files that must not), that a foreign key is rejected, and that the
recovered keys are well formed.

The verification tests matter most: a verifier that can only ever return an error
would pass every other test in the file, so there is an explicit test that the
mechanism returns *success* when the signature is genuine, and separate tests
that each altered byte invalidates it.

## Limitations

- **The payload cannot be decrypted.** Its key is RSA-wrapped with a private key
  held by the server. `explain` reports the framing and the signature, not the
  license contents, and does not pretend otherwise.
- **No real `.activation` file was available to test against**, since producing
  one requires a Bitwig license. The framing and signature logic are tested
  against files built to the format as reversed from the client; `synth` exists
  to make that testable end to end. The gap between "matches the reversed format"
  and "checked against a genuine file" is real and is not closed here.
- **The network protocol is described but not implemented.** The request framing,
  the nonce-keyed transform, and the MD5 handshake are documented in
  [RESEARCH.md](RESEARCH.md) because they were reversed, but this tool does not
  speak the protocol: without the server it would have nothing to talk to, and
  the response would be signed with the same key it cannot produce.

## License

MIT — see [LICENSE](LICENSE).
