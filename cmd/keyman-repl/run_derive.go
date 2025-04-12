package main

import (
	"fmt"
	"os"

	"github.com/oosawy/keyman/pkg/derive"
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

	info, err := derive.DerivePublicKey(derive.DeriveOptions{
		SealedPrivateKey: secBytes,
		MasterKey:        globalAesKey,
	})
	if err != nil {
		fmt.Fprintf(os.Stderr, "derive failed: %v\n", err)
		os.Exit(1)
	}

	fmt.Printf("public     : %x\n", info.PublicKey)
	fmt.Printf("fingerprint: %x\n", info.Fingerprint)
}
