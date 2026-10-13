# testdata

There is no checked-in fixture here, and that is deliberate rather than an
oversight.

## Why not a real license file

A genuine `.activation` file cannot be produced without a Bitwig license, and a
license cannot be obtained without buying one. So there is no real file to ship,
and a fabricated one presented as real would be worse than none.

## What the tests use instead

The tests build files in the process, using helpers in `parse_test.go`:

- `buildFile(material, key, payload)` frames the three content blocks exactly as
  the client's writer (`cmH`) does, followed by a placeholder signature block.
- `buildUnsignedBody(...)` returns the region a signature covers — the three
  content blocks without the signature block or its length prefix.
- `seal(body, priv)` signs that region and appends the signature block, which is
  what the client expects to read.

This means the framing and the signature logic are exercised without needing a
license, and `TestKeyBlockUses32BitLength` uses a 70,000-byte block so a 32-bit
length cannot be confused with a 16-bit one.

## What this does and does not establish

**Establishes**: the reader implements the framing that was reversed from `cml`
and `cmH`, and the signature check is Ed25519 over the region `cml` names.

**Does not establish**: that a real Bitwig file parses. That would require a real
file. The format here is the one read out of the client's own code, and until a
genuine sample is available the difference between "matches the reversed format"
and "matches Bitwig" stays open. It is recorded in README.md under Limitations
rather than closed by assertion.
