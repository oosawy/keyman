package keygen

import (
	"fmt"

	"github.com/oosawy/keyman/internal/keypair"
	"github.com/oosawy/keyman/internal/seal"
)

type GenerateOptions struct {
	MasterKey []byte
}

type KeyPair struct {
	SealedPrivateKey []byte
	PublicKey        []byte
	Fingerprint      []byte
}

func GenerateKeyPair(opts GenerateOptions) (*KeyPair, error) {
	key, err := keypair.GenP256KeyPair()
	if err != nil {
		return nil, fmt.Errorf("key generation failed: %w", err)
	}

	encoded, err := keypair.EncodeP256KeyPair(key)
	if err != nil {
		return nil, fmt.Errorf("key encoding failed: %w", err)
	}

	sealed, err := seal.SealPrivateKey(encoded.PrivateKey, opts.MasterKey)
	if err != nil {
		return nil, fmt.Errorf("seal failed: %w", err)
	}

	return &KeyPair{
		SealedPrivateKey: sealed,
		PublicKey:        encoded.PublicKey,
		Fingerprint:      encoded.Fingerprint,
	}, nil
}
