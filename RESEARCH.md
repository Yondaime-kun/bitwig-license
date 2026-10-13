# bitwig-license — research

Everything here is measured from Bitwig Studio 5.3.5 (`bitwig.jar`, 28,936
classes) or from the live service. Nothing is from documentation, because Bitwig
documents none of this.

## How the license subsystem was located

Class names are obfuscated (`clJ`, `cml`, `cmv`), so names are useless. String
constants are not obfuscated, so the way in is to grep for a distinctive string:

```
grep -rl 'services.bitwig.com' --include='*.class' .
  -> ./com/bitwig/flt/app/MCJ.class
```

One step located the whole subsystem. `strings` on the neighbouring classes then
produced the error contract before any decompiler was needed:

```
strings -n 6 SI.class | grep activation
  activation.could_not_reach_server
  activation.invalid_activation_file
  activation.invalid_host
  activation.invalid_license_version
  activation.invalid_response
  activation.invalid_serial
  activation.license_disabled
  activation.logged_out
  activation.login.host_disabled
  activation.old_activation_file
  activation.permanent_activation.could_not_write_activation_file
```

`Te.class` carries one more — `activation.permanent_activation.too_many_activations`.

## The service, measured live

```
GET   https://services.bitwig.com/v2  -> 405, Allow: POST, PUT, OPTIONS
HEAD                                  -> 405
OPTIONS                               -> 200, allow: POST,PUT,OPTIONS
POST  with no body                    -> 200, content-length: 0
POST  Content-Type: application/json  -> 415, "application/json is not supported"
POST  Content-Type: application/octet-stream -> 200
Server: Apache Tomcat/11.0.25
```

So the license service takes a binary body over POST/PUT. It is not REST, and it
rejects JSON explicitly.

## The client that talks to it

`clZ` is the HTTP client. Decompiled, its request path is:

```java
protected byte[] GS(String str, byte[] bArr, byte b, int i, Object... objArr) {
    byte[] nonce = GS();                       // 10 bytes from SecureRandom
    HttpPost post = new HttpPost(this.GS.toURI());
    post.setEntity(new ByteArrayEntity(GS(str, bArr, nonce, b, objArr)));
    HttpResponse r = client.execute(post);
    if (r.getStatusLine().getStatusCode() == 200)
        return GS(nonce, r);                   // decrypt response with the same nonce
    throw new clM("response status (...) was not ok");
}
```

The body it writes:

```
[cml.GS magic = ff ef df]
[cmH.GS(OutputStream, 11) -> 11 as uint16-little-endian]
[length-prefixed: bArr]
[cmF wrapping the stream with bArr as key]:
    writeUTF(server name)
    writeBytes(cmA.IgY())       <- the client identity list
    writeBytes(nonce)           <- the 10-byte random value
    write(byte b)
    for each arg: byte | int | long | float | double | boolean | UTF | map
```

The response is read back with the same nonce as key, and the first byte is a
status: `0` means the rest is the payload; anything else is an error code that
`cma` maps to one of the named errors above.

## The stream transform

`cmF` (write) and `cmD` (read) both wrap the byte stream in `cmG`/`cmE`, which is
a byte-wise transform keyed by the nonce:

```java
private int GS(int i) {
    if (this.IgY % 2 == 0)
        return ((i - key[IgY % key.length]) + 256) % 256;   // even position: subtract
    return i ^ key[IgY % key.length];                        // odd position: xor
}
```

and before any data is read, the responder must prove it knows the key:

```java
void GS() {                                   // cmE — the handshake
    byte[] want = MessageDigest.getInstance("MD5").digest(key);
    byte[] got = new byte[want.length];
    if (read(got) != want.length || !Arrays.equals(want, got))
        throw new cmC();
}
```

This is obfuscation, not secrecy: the key is sent in the clear in the same
message, and the digest is MD5 of that same key. It keeps a casual reader out and
stops nothing else.

## The license file

`cml.GS(byte[])` reads and verifies it. Signature first thing it does:

```java
Signature signature = Signature.getInstance("Ed25519");
signature.initVerify(this.IgY);                                  // a public key
signature.update(bArr, 0, (bArr.length - bArrMYk3.length) - 2);
if (!signature.verify(bArrMYk3))
    throw new cmp("License file could not be verified");
```

with

```java
private final PublicKey IgY = GS();

private static PublicKey GS() {
    return KeyFactory.getInstance("Ed25519").generatePublic(new X509EncodedKeySpec(
        Base64.getDecoder().decode(
            "MCowBQYDK2VwAyEA1u/XYBzjReOK+9nkC47fFHVMeaOG5JIKjsQlsq1lQvg=")));
}
```

**The signature is Ed25519, verified against a public key compiled into the
client.** The signature covers the file from the start up to the signature block
and its 2-byte length prefix.

The four blocks, in the order `cml` reads them:

| # | reader | length format | content |
| --- | --- | --- | --- |
| 1 | `cmH.MYk` | uint16 little-endian | material |
| 2 | `cmH.hEW` | **uint32 little-endian** | RSA-wrapped content key |
| 3 | `cmH.MYk` | uint16 little-endian | AES-encrypted payload |
| 4 | `cmH.MYk` | uint16 little-endian | Ed25519 signature (64 bytes) |

Block 2 is the odd one out, and it matters: read with a uint16 prefix it
consumes two bytes of the length as data and shifts every later offset, which
parses *successfully* into the wrong thing rather than failing. That is why the
endianness and width were read from `cmH` rather than assumed.

## The payload cipher

Two layers, both with keys the client does not have:

- `cmv` holds a **2048-bit RSA modulus** as a literal signed-byte array, and a
  public exponent `new cmI(new byte[]{1, 0, 1})` = 65537. It unwraps the content
  key from block 2.
- `cmu` is **AES-128 implemented by hand** — the `{99, 124, 119, 123, ...}` S-box,
  its inverse, and the Rcon table are all present as literals in the class.

`cmI` is a hand-rolled big-integer, not `java.math.BigInteger`; the modulus is
carried in it. RSA-2048 and AES-128 with the private half on Bitwig's server.

## The recovered public material

```
Ed25519 public key (raw 32 bytes):
  d6efd7601ce345e38afbd9e40b8edf14754c79a386e4920a8ec425b2ad6542f8
  base64 1u/XYBzjReOK+9nkC47fFHVMeaOG5JIKjsQlsq1lQvg=

X.509 SPKI the client decodes:
  MCowBQYDK2VwAyEA1u/XYBzjReOK+9nkC47fFHVMeaOG5JIKjsQlsq1lQvg=
  (30 2a 30 05 06 03 2b 65 70 03 21 00 ... — OID 1.3.101.112 is Ed25519)

RSA-2048 modulus:
  d026222e524e94aa…059fd601  (256 bytes, top byte 0xd0 so the 2048-bit bit is set)
  exponent 65537
```

Both are public by construction: the client needs them to verify, so anyone
holding the binary has them.

## What the payload contains

Not decrypted — it cannot be — but the reader that would consume it is visible in
`cml`, so the schema is known:

```
map   licences        (cmk, keyed by version)
map   licence types   (cmj, keyed by id)
[UTF] serial
[UTF] name
[int] something
[bool] something
[uint16 count] licences:
    [UTF] serial
    [bool] hasDate  -> [long] date
    [int]  licence type id -> looked up in the types map
    [uint16 count] features (cmo: name, key, two shorts, sub-features)
    [uint16 count] strings
[uint16][uint16] trial-marker (cms/cmt, dates)
[long] date
```

So a license carries a serial displayed as `XXXX-XXXX-XXXX-XXXX` (four 4-character
groups of a 16-character value, from `cmi.hEW()`), a type, features, and dates.

## Conclusion, and what it forces

The license is **Ed25519-signed by a key Bitwig holds privately**, and the
payload is **AES-128-encrypted under a key wrapped with RSA-2048**, private half
again on the server. This is plan case 3: no generator is possible from the
client alone, and no amount of client patching changes that, because the client
is not what produces the signature.

That is the honest ceiling, and it is a useful one: the framing and the
signature check need no secret, so a reader and verifier is a real tool that can
be built and tested, as long as it is not described as more than it is.
