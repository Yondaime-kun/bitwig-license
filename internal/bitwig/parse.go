// Package bitwig reads and verifies Bitwig Studio license files
// (Library/Application Support/Bitwig/Bitwig Studio/.activation-*).
//
// The format was reversed from Bitwig Studio 5.3.5 (bitwig.jar). Everything
// here is derived from decompiled client code, not from documentation, because
// Bitwig documents none of it:
//
//	cml.GS(byte[])   the file reader and signature check
//	cmv              RSA unwrap of the content key
//	cmu              AES-128 decrypt of the payload
//	cmH              length-prefixed byte blocks
//
// File layout, from cml.GS(byte[]):
//
//	[Ed25519 signature, at the end]
//	  ... and before it, in order:
//	  material  cmH.MYk — uint16-little-endian length, then bytes
//	  key       cmH.hEW — uint32-little-endian length, then bytes
//	  payload   cmH.MYk — uint16-little-endian length, then bytes
//	  signature cmH.MYk — uint16-little-endian length, then bytes
//
// The signature covers the whole file except the final signature block and its
// 2-byte length prefix: signature.update(bArr, 0, len - sigLen - 2).
//
// This package therefore has two layers of honesty:
//
//   - Parsing structure that needs no key: magic, block framing.
//   - Verification, which needs only public material.
//
// Decrypting the payload needs a content key that only Bitwig's server can
// produce, because it is RSA-wrapped with a private key. This package verifies
// and frames; it does not decrypt. See README.
package bitwig

import (
	"crypto/ed25519"
	"encoding/binary"
	"encoding/hex"
	"errors"
	"fmt"
)

// ErrNotLicense means the file does not begin with the license magic.
var ErrNotLicense = errors.New("not a Bitwig license file (bad magic)")

// ErrBadFrame means a length prefix points outside the file.
var ErrBadFrame = errors.New("license file is truncated or its framing is wrong")

// ErrSignature means the Ed25519 signature did not verify.
var ErrSignature = errors.New("license signature did not verify")

// Block is one length-prefixed byte block.
type Block struct {
	Offset int    // offset of the block's first data byte
	Length int    // number of data bytes
	Data   []byte // the data
}

// File is a parsed license file.
type File struct {
	// Raw is the file as read.
	Raw []byte

	// Material, Key, Payload, Signature are the four blocks cml reads in order.
	// Signature is the last block; the signature check covers everything before
	// the block's own 2-byte length prefix.
	Material  Block
	Key       Block
	Payload   Block
	Signature Block

	// SignedLen is how many bytes the Ed25519 signature covers.
	SignedLen int
}

// Magic returns the three-byte prefix every license file carries.
func Magic() []byte { return append([]byte(nil), LicenseMagic...) }

// readShort reads a block framed by a little-endian uint16 length. This is
// cmH.MYk(InputStream): a 2-byte little-endian length, then that many bytes.
// Note that clZ writes lengths as (length & 255) then (length >> 8) & 255,
// which is little-endian and not DataOutputStream.writeShort's big-endian.
func readShort(b []byte, pos int) (Block, int, error) {
	if pos+2 > len(b) {
		return Block{}, pos, fmt.Errorf("%w: length prefix at %d past end", ErrBadFrame, pos)
	}
	n := int(binary.LittleEndian.Uint16(b[pos : pos+2]))
	start := pos + 2
	if start+n > len(b) {
		return Block{}, pos, fmt.Errorf("%w: block at %d claims %d bytes, %d remain",
			ErrBadFrame, start, n, len(b)-start)
	}
	return Block{Offset: start, Length: n, Data: b[start : start+n]}, start + n, nil
}

// readInt reads a block framed by a little-endian uint32 length. This is
// cmH.hEW(InputStream) = GS(inputStream, IgY(inputStream)), and cml uses it for
// the *second* block only. Reading that block with a uint16 prefix would consume
// the top two bytes of its length as data, which yields a plausible but wrong
// offset instead of an error — the failure mode this distinction prevents.
func readInt(b []byte, pos int) (Block, int, error) {
	if pos+4 > len(b) {
		return Block{}, pos, fmt.Errorf("%w: 4-byte length prefix at %d past end", ErrBadFrame, pos)
	}
	n := int(binary.LittleEndian.Uint32(b[pos : pos+4]))
	start := pos + 4
	if n < 0 || start+n > len(b) {
		return Block{}, pos, fmt.Errorf("%w: long block at %d claims %d bytes, %d remain",
			ErrBadFrame, start, n, len(b)-start)
	}
	return Block{Offset: start, Length: n, Data: b[start : start+n]}, start + n, nil
}

// Parse reads the framing of a license file without verifying or decrypting it.
func Parse(raw []byte) (*File, error) {
	if len(raw) < len(LicenseMagic) {
		return nil, ErrNotLicense
	}
	for i, m := range LicenseMagic {
		if raw[i] != m {
			return nil, ErrNotLicense
		}
	}

	f := &File{Raw: raw}
	pos := len(LicenseMagic)

	var err error
	if f.Material, pos, err = readShort(raw, pos); err != nil {
		return nil, err
	}
	// cml reads this one with cmH.hEW, a 32-bit length.
	if f.Key, pos, err = readInt(raw, pos); err != nil {
		return nil, err
	}
	if f.Payload, pos, err = readShort(raw, pos); err != nil {
		return nil, err
	}
	if f.Signature, pos, err = readShort(raw, pos); err != nil {
		return nil, err
	}

	// cml verifies over len - sigLen - 2 bytes, i.e. up to but excluding the
	// signature block's own length prefix.
	f.SignedLen = f.Signature.Offset - 2
	if f.SignedLen < 0 || f.SignedLen > len(raw) {
		return nil, fmt.Errorf("%w: signed length %d", ErrBadFrame, f.SignedLen)
	}
	return f, nil
}

// Verify checks the Ed25519 signature over the file. It needs only the public
// key recovered from the client, so it runs offline.
func (f *File) Verify() error {
	if len(f.Signature.Data) != ed25519.SignatureSize {
		return fmt.Errorf("%w: signature is %d bytes, want %d",
			ErrSignature, len(f.Signature.Data), ed25519.SignatureSize)
	}
	pub := ed25519.PublicKey(ed25519PublicKeySlice())
	if !ed25519.Verify(pub, f.Raw[:f.SignedLen], f.Signature.Data) {
		return ErrSignature
	}
	return nil
}

// ed25519PublicKeySlice returns the recovered key as a slice without letting
// callers mutate the array.
func ed25519PublicKeySlice() []byte {
	k := make([]byte, len(Ed25519PublicKey))
	copy(k, Ed25519PublicKey[:])
	return k
}

// RSAModulus returns the recovered modulus as bytes.
func RSAModulus() ([]byte, error) { return hex.DecodeString(RSAModulusHex) }

// String summarizes the framing.
func (f *File) String() string {
	return fmt.Sprintf("license file: %d bytes, material=%d key=%d payload=%d signature=%d, signed=%d",
		len(f.Raw), f.Material.Length, f.Key.Length, f.Payload.Length,
		f.Signature.Length, f.SignedLen)
}
