package main

import (
	"fmt"

	"github.com/oosawy/keyman/pkg/api"
	"github.com/oosawy/keyman/pkg/sign"
)

func (k *KeymanKernel) Sign(args *api.KeymanKernelSignArgs, reply *api.KeymanKernelSignReply) error {
	sig, err := sign.SignMessage(sign.SignOptions{
		SealedPrivateKey: args.SecretKey,
		MasterKey:        k.masterKey,
		Message:          args.Message,
	})
	if err != nil {
		return fmt.Errorf("signing failed: %w", err)
	}

	reply.Signature = sig

	return nil
}
