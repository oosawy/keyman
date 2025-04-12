package derive

import (
	"fmt"

	"github.com/oosawy/keyman/internal/core/keypair"
	"github.com/oosawy/keyman/internal/core/seal"
)

type DeriveOptions struct {
	SealedPrivateKey []byte
	MasterKey        []byte
}

type DerivedPublicInfo struct {
	PublicKey   []byte
	Fingerprint []byte
}

func DerivePublicKey(opts DeriveOptions) (*DerivedPublicInfo, error) {
	unsealed, err := seal.UnsealPrivateKey(opts.SealedPrivateKey, opts.MasterKey)
	if err != nil {
		return nil, fmt.Errorf("unseal failed: %w", err)
	}

	priv, err := keypair.DecodeP256PrivateKey(unsealed)
	if err != nil {
		return nil, fmt.Errorf("key decoding failed: %w", err)
	}

	encoded, err := keypair.EncodeP256KeyPair(priv)
	if err != nil {
		return nil, fmt.Errorf("key encoding failed: %w", err)
	}

	return &DerivedPublicInfo{
		PublicKey:   encoded.PublicKey,
		Fingerprint: encoded.Fingerprint,
	}, nil
}
