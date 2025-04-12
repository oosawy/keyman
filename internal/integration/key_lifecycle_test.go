package integration_test

import (
	"encoding/hex"
	"testing"

	"github.com/oosawy/keyman/internal/cipherkit"
	"github.com/oosawy/keyman/internal/keypair"
	"github.com/oosawy/keyman/internal/seal"
)

func TestSealAndUnsealKeyPair(t *testing.T) {
	keyHex := "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"
	mkey, err := cipherkit.GetKeyAES(keyHex)
	if err != nil {
		t.Fatalf("GetKeyAES failed: %v", err)
	}

	key, err := keypair.GenP256KeyPair()
	if err != nil {
		t.Fatalf("GenP256KeyPair failed: %v", err)
	}

	encoded, err := keypair.EncodeP256KeyPair(key)
	if err != nil {
		t.Fatalf("EncodeP256KeyPair failed: %v", err)
	}

	sealed, err := seal.SealPrivateKey(encoded.PrivateKey, mkey)
	if err != nil {
		t.Fatalf("SealPrivateKey failed: %v", err)
	}

	unsealed, err := seal.UnsealPrivateKey(sealed, mkey)
	if err != nil {
		t.Fatalf("UnsealPrivateKey failed: %v", err)
	}

	if hex.EncodeToString(encoded.PrivateKey) != hex.EncodeToString(unsealed) {
		t.Errorf("Unsealed private key does not match original")
	}

	t.Logf("Public     : %s", hex.EncodeToString(encoded.PublicKey))
	t.Logf("Fingerprint: %s", hex.EncodeToString(encoded.Fingerprint))
}
