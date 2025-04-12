package main

import (
	"fmt"
	"os"

	"github.com/oosawy/keyman/pkg/keygen"
)

// keygen
func runKeygen(args []string) {
	fs := flagNew("keygen")
	fs.Parse(args)

	keyPair, err := keygen.GenerateKeyPair(keygen.GenerateOptions{
		MasterKey: globalAesKey,
	})
	if err != nil {
		fmt.Fprintf(os.Stderr, "key generation failed: %v\n", err)
		os.Exit(1)
	}

	fmt.Printf("secret key : %x\n", keyPair.SealedPrivateKey)
	fmt.Printf("public key : %x\n", keyPair.PublicKey)
	fmt.Printf("fingerprint: %x\n", keyPair.Fingerprint)
}
