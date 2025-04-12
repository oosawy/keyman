package main

import (
	"fmt"
	"os"

	"github.com/oosawy/keyman/internal/keypair"
	"github.com/oosawy/keyman/internal/seal"
)

// keygen
func runKeygen(args []string) {
	fs := flagNew("keygen")
	fs.Parse(args)

	key, err := keypair.GenP256KeyPair()
	if err != nil {
		fmt.Fprintf(os.Stderr, "key generation failed: %v\n", err)
		return
	}

	encoded, err := keypair.EncodeP256KeyPair(key)
	if err != nil {
		fmt.Fprintf(os.Stderr, "key encoding failed: %v\n", err)
		return
	}

	sealed, err := seal.SealPrivateKey(encoded.PrivateKey, globalAesKey)
	if err != nil {
		fmt.Fprintf(os.Stderr, "seal failed: %v\n", err)
		return
	}

	fmt.Printf("secret key : %x\n", sealed)
	fmt.Printf("public key : %x\n", encoded.PublicKey)
	fmt.Printf("fingerprint: %x\n", encoded.Fingerprint)
}
