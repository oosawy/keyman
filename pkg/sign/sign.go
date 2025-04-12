package sign

import (
	"fmt"

	"github.com/oosawy/keyman/internal/core/keypair"
	"github.com/oosawy/keyman/internal/core/seal"
)

type SignOptions struct {
	SealedPrivateKey []byte
	MasterKey        []byte
	Message          []byte
}

func SignMessage(opts SignOptions) ([]byte, error) {
	unsealed, err := seal.UnsealPrivateKey(opts.SealedPrivateKey, opts.MasterKey)
	if err != nil {
		return nil, fmt.Errorf("unseal failed: %w", err)
	}

	priv, err := keypair.DecodeP256PrivateKey(unsealed)
	if err != nil {
		return nil, fmt.Errorf("key decoding failed: %w", err)
	}

	sig, err := keypair.Sign(priv, opts.Message)
	if err != nil {
		return nil, fmt.Errorf("signing failed: %w", err)
	}

	return sig, nil
}
