package main

import (
	"fmt"
	"os"

	"github.com/oosawy/keyman/internal/keypair"
	"github.com/oosawy/keyman/internal/seal"
)

// derive --secret SECRET_KEY_HEX
func runDerive(args []string) {
	fs := flagNew("derive")
	secret := fs.String("secret", "", "Secret key (hex)")
	fs.Parse(args)

	if *secret == "" {
		fs.Usage()
		return
	}

	secBytes := mustDecodeHex("secret", *secret)

	unsealed, err := seal.UnsealPrivateKey(secBytes, globalAesKey)
	if err != nil {
		fmt.Fprintf(os.Stderr, "unseal failed: %v\n", err)
		return
	}

	priv, err := keypair.DecodeP256PrivateKey(unsealed)
	if err != nil {
		fmt.Fprintf(os.Stderr, "key decoding failed: %v\n", err)
		return
	}

	encoded, err := keypair.EncodeP256KeyPair(priv)
	if err != nil {
		fmt.Fprintf(os.Stderr, "key encoding failed: %v\n", err)
		return
	}

	fmt.Printf("public     : %x\n", encoded.PublicKey)
	fmt.Printf("fingerprint: %x\n", encoded.Fingerprint)
}
