package main

import (
	"fmt"
	"os"

	"github.com/oosawy/keyman/internal/keypair"
	"github.com/oosawy/keyman/internal/seal"
)

// sign --secret SECRET_KEY_HEX --message MESSAGE
func runSign(args []string) {
	fs := flagNew("sign")
	secret := fs.String("secret", "", "Secret key (hex)")
	message := fs.String("message", "", "Message to sign")
	fs.Parse(args)

	if *secret == "" || *message == "" {
		fs.Usage()
		return
	}

	secBytes := mustDecodeHex("secret", *secret)
	msgBytes := []byte(*message)

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

	sig, err := keypair.Sign(priv, msgBytes)
	if err != nil {
		fmt.Fprintf(os.Stderr, "")
		return
	}

	fmt.Printf("signature: %x\n", sig)
}
