package seal_test

import (
	"bytes"
	"testing"

	"github.com/oosawy/keyman/internal/seal"
)

func TestSealAndUnsealPrivateKey(t *testing.T) {
	priv := []byte("my-secret-private-key")
	mkey := []byte("0123456789abcdef0123456789abcdef")

	sealed, err := seal.SealPrivateKey(priv, mkey)
	if err != nil {
		t.Fatalf("SealPrivateKey failed: %v", err)
	}

	if !bytes.Equal(sealed[:2], []byte("km")) {
		t.Fatalf("expected header to be \"km\", got %q", sealed[:2])
	}

	unsealed, err := seal.UnsealPrivateKey(sealed, mkey)
	if err != nil {
		t.Fatalf("UnsealPrivateKey failed: %v", err)
	}

	if !bytes.Equal(priv, unsealed) {
		t.Errorf("Unsealed key does not match original.\nExpected: %x\nGot:      %x", priv, unsealed)
	}
}
