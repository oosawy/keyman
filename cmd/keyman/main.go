package main

import (
	"encoding/hex"
	"fmt"
	"os"

	"github.com/oosawy/keyman/internal/cipherkit"
	"github.com/oosawy/keyman/internal/keygen"
	"github.com/oosawy/keyman/internal/seal"
)

func main() {
	keyHex := os.Getenv("AES_KEY_HEX")
	mkey, err := cipherkit.GetKeyAES(keyHex)
	if err != nil {
		panic(err)
	}

	key, err := keygen.GenP256KeyPair()
	if err != nil {
		panic(err)
	}

	priv, pub, fp, err := keygen.EncodeP256KeyPair(key)
	if err != nil {
		panic(err)
	}

	sealed, err := seal.SealPrivateKey(priv, mkey)
	if err != nil {
		panic(err)
	}

	fmt.Printf("Sealed     : %s\n", hex.EncodeToString(sealed))
	fmt.Printf("Public     : %s\n", hex.EncodeToString(pub))
	fmt.Printf("Fingerprint: %s\n", hex.EncodeToString(fp))
}
