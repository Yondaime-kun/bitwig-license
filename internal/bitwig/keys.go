package bitwig

// Artifacts recovered from Bitwig Studio 5.3.5 (bitwig.jar, 28,936 classes).
//
// Both are string/array constants inside the client, so they are public by
// definition: the client needs them to verify, which means anyone holding the
// binary has them. Recovering them is not a break of anything — it is what makes
// a license file checkable (and explainable) outside Bitwig.
//
// Ed25519 public key, from cml.GS():
//
//	Base64.getDecoder().decode(
//	  "MCowBQYDK2VwAyEA1u/XYBzjReOK+9nkC47fFHVMeaOG5JIKjsQlsq1lQvg=")
//
// The blob is an X.509 SubjectPublicKeyInfo: 30 2a 30 05 06 03 2b 65 70 03 21 00
// (SEQUENCE, SEQUENCE, OID 1.3.101.112, BIT STRING) followed by the 32-byte key.
// The raw key below is that trailing 32 bytes, so the SPKI wrapper does not need
// to be parsed to use it.
//
// RSA-2048 modulus, from the static initialiser of cmv, the class that unwraps
// the AES key. The Java literal is a signed byte array; modulusHex is the same
// bytes as a positive integer, with the leading 0x00 sign byte that a 2048-bit
// two's-complement magnitude requires.
//
// The RSA public exponent is the literal `new cmI(new byte[]{1, 0, 1})` in the
// same class — 65537.

// Ed25519PublicKey is the 32-byte raw Ed25519 public key that verifies Bitwig
// license files.
var Ed25519PublicKey = [32]byte{
	0xd6, 0xef, 0xd7, 0x60, 0x1c, 0xe3, 0x45, 0xe3,
	0x8a, 0xfb, 0xd9, 0xe4, 0x0b, 0x8e, 0xdf, 0x14,
	0x75, 0x4c, 0x79, 0xa3, 0x86, 0xe4, 0x92, 0x0a,
	0x8e, 0xc4, 0x25, 0xb2, 0xad, 0x65, 0x42, 0xf8,
}

// Ed25519PublicKeySPKI is the base64 X.509 SubjectPublicKeyInfo the client
// decodes, kept verbatim so the recovery can be checked against the source.
const Ed25519PublicKeySPKI = "MCowBQYDK2VwAyEA1u/XYBzjReOK+9nkC47fFHVMeaOG5JIKjsQlsq1lQvg="

// RSAModulusHex is the 2048-bit RSA modulus from cmv, big-endian, 256 bytes
// once the leading sign byte is dropped.
const RSAModulusHex = "d026222e524e94aaf086e27df944073042471f3b9173cbf614ebb9ea2e6dfbc5d9d11faed95c1063f3ae55b7dcb5bade3e12b43df60eed264726e453d59068b7871528da865a97fc49639a679f62d4d1a5f77ba9782fcc60d4c875266bf3f9c7fb5ac394dd342f14f4906cf2cfe00da48ba166bc9c50e2568982ebb07ef8eec52f27158db3d6cdac46f2cb646ba1cd01103a8d4d079ec5c4332eddfa8ddbb343aeaa2975f50448faed275645891f8e8b2eb6f384c3f5fad53e95c94622fc37fbd303455d47cd9802ea932da84602cbdefa1d686059ab3fd26c3539e2bf6ba638c325001e38ac5fa61be5f401062240b24b5f06b44f60c981afbef170059fd601"

// RSAExponent is the public exponent from cmv: cmI{1,0,1} = 65537.
const RSAExponent = 65537

// LicenseMagic is the three-byte prefix of a license file, cml.GS = {-1,-17,-33}.
var LicenseMagic = []byte{0xff, 0xef, 0xdf}
