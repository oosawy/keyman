package seal

import (
	"bytes"
	"errors"

	"github.com/oosawy/keyman/internal/crypto"
)

var sealHeader = []byte{'k', 'm'}

func SealPrivateKey(priv, mkey []byte) ([]byte, error) {
	nonce, encrypted, err := crypto.EncryptGCM(priv, mkey)
	if err != nil {
		return nil, err
	}

	buf := make([]byte, 0, len(sealHeader)+len(nonce)+len(encrypted))
	buf = append(buf, sealHeader...)
	buf = append(buf, nonce...)
	buf = append(buf, encrypted...)
	return buf, nil
}

func UnsealPrivateKey(data []byte) (nonce, sealed []byte, err error) {
	hlen := len(sealHeader)

	if len(data) < hlen {
		err = errors.New("data too short")
		return
	}
	if !bytes.Equal(data[:hlen], sealHeader) {
		err = errors.New("invalid header")
		return
	}
	if len(data) < hlen+crypto.GCMNonceSize {
		err = errors.New("data too short for nonce")
		return
	}

	nonce = data[hlen : hlen+crypto.GCMNonceSize]
	sealed = data[hlen+crypto.GCMNonceSize:]
	return
}
