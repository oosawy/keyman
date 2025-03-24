package main

import (
	"fmt"
	"os"

	"github.com/oosawy/keyman/internal/keypair"
)

// verify --public PUBLIC_KEY_HEX --message MESSAGE --signature HEX
func runVerify(args []string) {
	fs := flagNew("verify")
	public := fs.String("public", "", "Public key (hex)")
	message := fs.String("message", "", "Message to verify")
	signature := fs.String("signature", "", "Signature (hex)")
	fs.Parse(args)

	if *public == "" || *message == "" || *signature == "" {
		fs.Usage()
		return
	}

	pubBytes := mustDecodeHex("public", *public)
	msgBytes := []byte(*message)
	sigBytes := mustDecodeHex("signature", *signature)

	pub, err := keypair.DecodeP256PublicKey(pubBytes)
	if err != nil {
		fmt.Fprintf(os.Stderr, "key decoding failed: %v", err)
	}

	valid := keypair.Verify(pub, msgBytes, sigBytes)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Verification failed: %v\n", err)
		return
	}

	if valid {
		fmt.Println("Signature is valid")
	} else {
		fmt.Println("Signature is invalid")
	}
}
