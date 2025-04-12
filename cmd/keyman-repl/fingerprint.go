package main

import (
	"fmt"
	"os"

	"github.com/oosawy/keyman/internal/core/keypair"
	"github.com/oosawy/keyman/internal/core/seal"
)

// fingerprint [--public PUBLIC_KEY_HEX] | [--secret SECRET_KEY_HEX]
func runFingerprint(args []string) {
	fs := flagNew("fingerprint")
	public := fs.String("public", "", "Public key (hex)")
	secret := fs.String("secret", "", "Secret key (hex)")
	fs.Parse(args)

	if *public == "" && *secret == "" {
		fs.Usage()
		return
	}

	if *public != "" {
		bytes := mustDecodeHex("public", *public)
		fp := keypair.Fingerprint(bytes)
		fmt.Printf("fingerprint: %x\n", fp)
		return
	}

	if *secret != "" {
		bytes := mustDecodeHex("secret", *secret)
		unsealed, err := seal.UnsealPrivateKey(bytes, globalAesKey)
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

		fmt.Printf("fingerprint: %x\n", encoded.Fingerprint)
		return
	}

}
