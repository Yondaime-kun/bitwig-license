// Command bitwig-license explains and verifies Bitwig Studio license files.
//
//	bitwig-license explain <file>   show the structure and what can be read
//	bitwig-license verify  <file>   check the Ed25519 signature
//	bitwig-license keys             print the recovered public material
//	bitwig-license synth  <file>    write a signed sample in the real framing
//
// The explain and verify commands work on a real .activation file. synth exists
// so the tool can be exercised end to end without one: it produces a correctly
// framed file signed with a key of its own, which verify will reject (it is not
// Bitwig's key) and which synth --key prints so the framing can be checked
// against a key you hold. That separation is the point — see README.
package main

import (
	"crypto/ed25519"
	"crypto/rand"
	"encoding/base64"
	"encoding/binary"
	"flag"
	"fmt"
	"os"

	"github.com/yondaime-kun/bitwig-license/internal/bitwig"
)

func main() {
	if len(os.Args) < 2 {
		usage()
		os.Exit(2)
	}

	switch os.Args[1] {
	case "explain":
		cmdExplain(os.Args[2:])
	case "verify":
		cmdVerify(os.Args[2:])
	case "keys":
		cmdKeys()
	case "synth":
		cmdSynth(os.Args[2:])
	case "-h", "--help", "help":
		usage()
	default:
		fmt.Fprintf(os.Stderr, "unknown command %q\n\n", os.Args[1])
		usage()
		os.Exit(2)
	}
}

func usage() {
	fmt.Fprint(os.Stderr, `bitwig-license — explain and verify Bitwig Studio license files

  bitwig-license explain <file>   show framing and what each block is
  bitwig-license verify  <file>   check the Ed25519 signature over the file
  bitwig-license keys             print the recovered public key and modulus
  bitwig-license synth  <file>    write a signed sample file in the real framing
`)
}

func readFile(path string) []byte {
	b, err := os.ReadFile(path)
	if err != nil {
		fatal(err)
	}
	return b
}

func fatal(err error) {
	fmt.Fprintln(os.Stderr, "bitwig-license:", err)
	os.Exit(1)
}

func cmdExplain(args []string) {
	if len(args) != 1 {
		usage()
		os.Exit(2)
	}
	raw := readFile(args[0])
	f, err := bitwig.Parse(raw)
	if err != nil {
		fatal(err)
	}

	fmt.Printf("file      %s\n", args[0])
	fmt.Printf("size      %d bytes\n", len(raw))
	fmt.Printf("magic     %02x %02x %02x  (cml.GS)\n",
		bitwig.Magic()[0], bitwig.Magic()[1], bitwig.Magic()[2])
	fmt.Println()
	fmt.Println("blocks, in the order cml reads them:")
	fmt.Printf("  material   offset %6d  %6d bytes   uint16 length prefix\n", f.Material.Offset, f.Material.Length)
	fmt.Printf("  key        offset %6d  %6d bytes   uint32 length prefix\n", f.Key.Offset, f.Key.Length)
	fmt.Printf("  payload    offset %6d  %6d bytes   uint16 length prefix\n", f.Payload.Offset, f.Payload.Length)
	fmt.Printf("  signature  offset %6d  %6d bytes   uint16 length prefix\n", f.Signature.Offset, f.Signature.Length)
	fmt.Println()
	fmt.Printf("signed region: first %d bytes (file length minus the signature block and its prefix)\n", f.SignedLen)

	v := "no"
	if f.Verify() == nil {
		v = "yes"
	}
	fmt.Printf("signature valid under the recovered Bitwig key: %s\n", v)
	fmt.Println()
	fmt.Println("what this means:")
	fmt.Println("  - the framing above is read without any key, and is correct for the bytes given")
	fmt.Println("  - the payload stays encrypted: its key is RSA-wrapped with a private key")
	fmt.Println("    held by Bitwig's server, so it cannot be decrypted from the client alone")
}

func cmdVerify(args []string) {
	if len(args) != 1 {
		usage()
		os.Exit(2)
	}
	raw := readFile(args[0])
	f, err := bitwig.Parse(raw)
	if err != nil {
		fatal(err)
	}
	if err := f.Verify(); err != nil {
		fmt.Printf("INVALID  %s\n", err)
		os.Exit(1)
	}
	fmt.Printf("VALID    %s: signature verifies under the recovered Bitwig key\n", args[0])
}

func cmdKeys() {
	fmt.Printf("Ed25519 public key (raw, %d bytes)\n", len(bitwig.Ed25519PublicKey))
	fmt.Printf("  hex    %x\n", bitwig.Ed25519PublicKey)
	fmt.Printf("  base64 %s\n", base64.StdEncoding.EncodeToString(bitwig.Ed25519PublicKey[:]))
	fmt.Println()
	fmt.Printf("Ed25519 public key (X.509 SPKI, as the client decodes it)\n")
	fmt.Printf("  base64 %s\n", bitwig.Ed25519PublicKeySPKI)
	fmt.Println()
	m, err := bitwig.RSAModulus()
	if err != nil {
		fatal(err)
	}
	fmt.Printf("RSA public key (unwraps the content key)\n")
	fmt.Printf("  modulus  %d bytes (%d bits)\n", len(m), len(m)*8)
	fmt.Printf("  exponent %d\n", bitwig.RSAExponent)
	fmt.Println()
	fmt.Println("Both are constants inside Bitwig Studio 5.3.5; see internal/bitwig/keys.go.")
}

func cmdSynth(args []string) {
	fs := flag.NewFlagSet("synth", flag.ExitOnError)
	out := fs.String("o", "", "output file")
	fs.Parse(args)

	path := *out
	if path == "" {
		if fs.NArg() > 0 {
			path = fs.Arg(0)
		} else {
			usage()
			os.Exit(2)
		}
	}

	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		fatal(err)
	}

	// Frame it the way the client does, then sign the content region.
	material := []byte("iv-material-16by")
	key := []byte("this stands in for the rsa-wrapped content key")
	payload := []byte("this stands in for the aes-encrypted payload")

	body := frame(material, key, payload)
	sig := ed25519.Sign(priv, body)
	file := append(body, lenPrefix(len(sig))...)
	file = append(file, sig...)

	if err := os.WriteFile(path, file, 0o644); err != nil {
		fatal(err)
	}

	fmt.Printf("wrote %s (%d bytes)\n", path, len(file))
	fmt.Printf("signed with a freshly generated key, NOT Bitwig's:\n")
	fmt.Printf("  public  %s\n", base64.StdEncoding.EncodeToString(pub))
	fmt.Printf("verify will reject this file, by design — the point of synth is to\n")
	fmt.Printf("exercise the framing, not to produce a license Bitwig would accept.\n")
}

// frame writes the three content blocks with the framing the client uses.
func frame(material, key, payload []byte) []byte {
	var out []byte
	out = append(out, bitwig.Magic()...)
	out = append(out, lenPrefix(len(material))...)
	out = append(out, material...)
	out = append(out, intPrefix(len(key))...)
	out = append(out, key...)
	out = append(out, lenPrefix(len(payload))...)
	out = append(out, payload...)
	return out
}

func lenPrefix(n int) []byte {
	b := make([]byte, 2)
	binary.LittleEndian.PutUint16(b, uint16(n))
	return b
}

func intPrefix(n int) []byte {
	b := make([]byte, 4)
	binary.LittleEndian.PutUint32(b, uint32(n))
	return b
}
