package bitwig

import (
	"bytes"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/base64"
	"encoding/binary"
	"strings"
	"testing"
)

// buildFile frames a license file the way clZ.GS(OutputStream,byte[]) does:
// magic, then each block as a little-endian uint16 length followed by the bytes.
func buildFile(material, key, payload []byte) []byte {
	var b bytes.Buffer
	b.Write(LicenseMagic)
	writeShort := func(p []byte) {
		var l [2]byte
		binary.LittleEndian.PutUint16(l[:], uint16(len(p)))
		b.Write(l[:])
		b.Write(p)
	}
	writeInt := func(p []byte) {
		var l [4]byte
		binary.LittleEndian.PutUint32(l[:], uint32(len(p)))
		b.Write(l[:])
		b.Write(p)
	}
	writeShort(material)
	writeInt(key) // cml reads the key block with cmH.hEW, a 32-bit length
	writeShort(payload)
	// A real file always ends with a signature block; cml reads it as the
	// fourth block rather than locating it some other way. Framing tests need
	// the block present even when they are not testing the signature itself, so
	// buildFile appends a placeholder of the right size.
	writeShort(make([]byte, ed25519.SignatureSize))
	return b.Bytes()
}

// buildUnsignedBody returns the framed region the signature covers: the three
// content blocks, without the signature block or its length prefix.
func buildUnsignedBody(material, key, payload []byte) []byte {
	full := buildFile(material, key, payload)
	return full[:len(full)-2-ed25519.SignatureSize]
}

// seal signs a framed file and appends the signature block, producing a file
// the client would accept the signature of.
func seal(body []byte, priv ed25519.PrivateKey) []byte {
	sig := ed25519.Sign(priv, body)
	out := append([]byte(nil), body...)
	var l [2]byte
	binary.LittleEndian.PutUint16(l[:], uint16(len(sig)))
	out = append(out, l[:]...)
	out = append(out, sig...)
	return out
}

// signedFile is the common case: frame the three content blocks, sign exactly
// that region, and append the signature block, which is what the client does.
func signedFile(material, key, payload []byte, priv ed25519.PrivateKey) []byte {
	return seal(buildUnsignedBody(material, key, payload), priv)
}

func keys(t *testing.T) (ed25519.PublicKey, ed25519.PrivateKey) {
	t.Helper()
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("GenerateKey: %v", err)
	}
	return pub, priv
}

func TestParseFraming(t *testing.T) {
	raw := buildFile([]byte("IV-MATERIAL"), []byte("WRAPPED-KEY"), []byte("CIPHERTEXT"))
	f, err := Parse(raw)
	if err != nil {
		t.Fatalf("Parse: %v", err)
	}
	if got := string(f.Material.Data); got != "IV-MATERIAL" {
		t.Errorf("Material = %q, want %q", got, "IV-MATERIAL")
	}
	if got := string(f.Key.Data); got != "WRAPPED-KEY" {
		t.Errorf("Key = %q, want %q", got, "WRAPPED-KEY")
	}
	if got := string(f.Payload.Data); got != "CIPHERTEXT" {
		t.Errorf("Payload = %q, want %q", got, "CIPHERTEXT")
	}
}

func TestRejectsBadMagic(t *testing.T) {
	raw := buildFile([]byte("a"), []byte("b"), []byte("c"))
	raw[0] = 0x00
	if _, err := Parse(raw); err != ErrNotLicense {
		t.Fatalf("err = %v, want ErrNotLicense", err)
	}
}

func TestRejectsTruncatedFraming(t *testing.T) {
	// A block length that runs past the end must be caught, not read.
	raw := append([]byte(nil), LicenseMagic...)
	raw = append(raw, 0xff, 0xff) // claims 65535 bytes, provides none
	if _, err := Parse(raw); err == nil {
		t.Fatal("expected an error for a block that runs past the end")
	}
}

// TestLengthIsLittleEndian pins the endianness. clZ writes length & 255 first,
// so a 256-byte block has prefix 00 01. If the code read it as big-endian it
// would see 1 and the parse would be wrong by 255 bytes — a silent corruption
// rather than a crash, which is exactly the kind of bug this pins.
func TestLengthIsLittleEndian(t *testing.T) {
	blob := bytes.Repeat([]byte{0xAB}, 256)
	raw := buildFile(blob, []byte("k"), []byte("p"))
	f, err := Parse(raw)
	if err != nil {
		t.Fatalf("Parse: %v", err)
	}
	if f.Material.Length != 256 {
		t.Errorf("Material.Length = %d, want 256", f.Material.Length)
	}
	if !bytes.Equal(f.Material.Data, blob) {
		t.Error("Material data does not match the 256-byte block written")
	}
}

// TestVerifyAcceptsAGenuineSignature proves the verification path actually runs
// and can return success, using a key we control rather than Bitwig's. Without
// this the verifier could be broken in a way that only ever returns an error and
// every other test would still pass.
func TestVerifyAcceptsAGenuineSignature(t *testing.T) {
	_, priv := keys(t)
	body := buildUnsignedBody([]byte("iv"), []byte("key"), []byte("payload"))
	raw := seal(body, priv)

	// The package verifies with Bitwig's key, not ours, so check the mechanism
	// directly here: parse, then verify with the key that signed it.
	f, err := Parse(raw)
	if err != nil {
		t.Fatalf("Parse: %v", err)
	}
	if !ed25519.Verify(priv.Public().(ed25519.PublicKey), f.Raw[:f.SignedLen], f.Signature.Data) {
		t.Fatal("a signature we just produced did not verify")
	}
}

// TestPackageVerifyRejectsForeignKey confirms the shipped verifier is bound to
// Bitwig's recovered key and does not accept a file signed by someone else.
func TestPackageVerifyRejectsForeignKey(t *testing.T) {
	_, priv := keys(t)
	raw := signedFile([]byte("iv"), []byte("key"), []byte("payload"), priv)
	f, err := Parse(raw)
	if err != nil {
		t.Fatalf("Parse: %v", err)
	}
	if err := f.Verify(); err == nil {
		t.Fatal("Verify accepted a file signed by a key that is not Bitwig's")
	}
}

// TestVerifyRejectsTamperedFile mutates each field of a file signed with our own
// key and checks the signature over it no longer holds. This is the property
// that matters: a single changed byte must invalidate the signature.
func TestVerifyRejectsTamperedFile(t *testing.T) {
	_, priv := keys(t)
	pub := priv.Public().(ed25519.PublicKey)

	base := signedFile([]byte("iv-material"), []byte("wrapped-key"), []byte("payload-bytes"), priv)

	mutations := []struct {
		name string
		fn   func([]byte) []byte
	}{
		{"flip a payload byte", func(b []byte) []byte { b[len(b)/2] ^= 0x01; return b }},
		{"flip the magic", func(b []byte) []byte { b[0] ^= 0x01; return b }},
		{"flip a signature byte", func(b []byte) []byte { b[len(b)-1] ^= 0x01; return b }},
		{"truncate", func(b []byte) []byte { return b[:len(b)-1] }},
	}

	for _, m := range mutations {
		t.Run(m.name, func(t *testing.T) {
			raw := m.fn(append([]byte(nil), base...))
			f, err := Parse(raw)
			if err != nil {
				// A truncated file failing to parse is also a rejection.
				return
			}
			if f.SignedLen > len(f.Raw) {
				return
			}
			if ed25519.Verify(pub, f.Raw[:f.SignedLen], f.Signature.Data) {
				t.Fatalf("signature still verified after: %s", m.name)
			}
		})
	}
}

func TestSignedLenExcludesSignaturePrefix(t *testing.T) {
	_, priv := keys(t)
	body := buildUnsignedBody([]byte("iv"), []byte("key"), []byte("payload"))
	raw := seal(body, priv)
	f, err := Parse(raw)
	if err != nil {
		t.Fatalf("Parse: %v", err)
	}
	// The signature covers everything up to the signature block's length prefix.
	// body is exactly that region, so SignedLen must equal len(body).
	if f.SignedLen != len(body) {
		t.Errorf("SignedLen = %d, want %d (the signed region)", f.SignedLen, len(body))
	}
	// And the signature must be over exactly those bytes.
	if !ed25519.Verify(priv.Public().(ed25519.PublicKey), body, f.Signature.Data) {
		t.Error("the signed region is not the bytes the signature was made over")
	}
}

func TestRecoveredKeysAreWellFormed(t *testing.T) {
	if len(Ed25519PublicKey) != ed25519.PublicKeySize {
		t.Errorf("Ed25519 key is %d bytes, want %d", len(Ed25519PublicKey), ed25519.PublicKeySize)
	}
	m, err := RSAModulus()
	if err != nil {
		t.Fatalf("RSAModulus: %v", err)
	}
	if len(m) != 256 {
		t.Errorf("RSA modulus is %d bytes, want 256", len(m))
	}
	// A 2048-bit modulus has its top bit set, so the first byte is >= 0x80.
	if m[0] < 0x80 {
		t.Errorf("modulus top byte is %#x, want >= 0x80 for a 2048-bit modulus", m[0])
	}
	if RSAExponent != 65537 {
		t.Errorf("RSA exponent = %d, want 65537", RSAExponent)
	}
}

func TestSPKIMatchesRawKey(t *testing.T) {
	// The recovered SPKI ends with the 32-byte key; if these two ever drift, one
	// of them was edited by hand and the recovery is no longer trustworthy.
	spki, err := base64Decode(Ed25519PublicKeySPKI)
	if err != nil {
		t.Fatalf("decode SPKI: %v", err)
	}
	if !strings.Contains(Ed25519PublicKeySPKI, "-") && len(spki) == 0 {
		t.Fatal("SPKI decoded to nothing")
	}
	if len(spki) != 44 {
		t.Fatalf("SPKI is %d bytes, want 44", len(spki))
	}
	if !bytes.Equal(spki[12:], Ed25519PublicKey[:]) {
		t.Error("SPKI trailing 32 bytes do not equal the raw key")
	}
}

func base64Decode(s string) ([]byte, error) { return base64.StdEncoding.DecodeString(s) }

// TestKeyBlockUses32BitLength pins the one block whose length is a uint32. cml
// reads block[1] with cmH.hEW rather than cmH.MYk; if the parser used a uint16
// there it would take the top two bytes of the length as the first two bytes of
// data and still "succeed", shifting every later offset. A 70,000-byte key block
// only fits in 32 bits, so it cannot be confused with the 16-bit form.
func TestKeyBlockUses32BitLength(t *testing.T) {
	key := bytes.Repeat([]byte{0x5A}, 70000)
	raw := buildFile([]byte("iv"), key, []byte("payload"))
	f, err := Parse(raw)
	if err != nil {
		t.Fatalf("Parse: %v", err)
	}
	if f.Key.Length != 70000 {
		t.Errorf("Key.Length = %d, want 70000", f.Key.Length)
	}
	if !bytes.Equal(f.Key.Data, key) {
		t.Error("Key data does not match the 70,000-byte block written")
	}
	if got := string(f.Payload.Data); got != "payload" {
		t.Errorf("Payload = %q; a wrong key length would have shifted this", got)
	}
}
