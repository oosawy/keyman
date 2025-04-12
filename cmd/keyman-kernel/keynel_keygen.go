package main

import (
	"fmt"

	"github.com/oosawy/keyman/pkg/api"
	"github.com/oosawy/keyman/pkg/keygen"
)

func (k *KeymanKernel) Keygen(args *api.KeymanKernelArgs, reply *api.KeymanKernelReply) error {
	keyPair, err := keygen.GenerateKeyPair(keygen.GenerateOptions{
		MasterKey: k.masterKey,
	})
	if err != nil {
		return fmt.Errorf("key generation failed: %w", err)
	}

	reply.SecretKey = keyPair.SealedPrivateKey
	reply.PublicKey = keyPair.PublicKey
	reply.Fingerprint = keyPair.Fingerprint

	return nil
}
