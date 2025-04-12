package main

import (
	"fmt"
	"os"

	"github.com/oosawy/keyman/pkg/sign"
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

	sig, err := sign.SignMessage(sign.SignOptions{
		SealedPrivateKey: secBytes,
		MasterKey:        globalAesKey,
		Message:          msgBytes,
	})
	if err != nil {
		fmt.Fprintf(os.Stderr, "signing failed: %v\n", err)
		os.Exit(1)
	}

	fmt.Printf("signature: %x\n", sig)
}
