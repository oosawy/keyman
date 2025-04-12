package main

import (
	"fmt"

	"github.com/oosawy/keyman/pkg/api"
	"github.com/oosawy/keyman/pkg/derive"
)

func (k KeymanKernel) Derive(args api.KeymanKernelDeriveArgs, reply *api.KeymanKernelDeriveReply) error {
	info, err := derive.DerivePublicKey(derive.DeriveOptions{
		SealedPrivateKey: args.SecretKey,
		MasterKey:        k.masterKey,
	})
	if err != nil {
		return fmt.Errorf("deriving public key failed: %w", err)
	}

	reply.PublicKey = info.PublicKey
	reply.Fingerprint = info.Fingerprint

	return nil
}
