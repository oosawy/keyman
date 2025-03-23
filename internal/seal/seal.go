package seal

import (
	"bytes"
	"errors"

	"github.com/oosawy/keyman/internal/cipherkit"
)

var sealHeader = []byte{'k', 'm'}

func SealPrivateKey(priv, mkey []byte) (sealed []byte, err error) {
	nonce, encrypted, err := cipherkit.EncryptGCM(priv, mkey)
	if err != nil {
		return
	}

	sealed = marshal(nonce, encrypted)
	return
}

func UnsealPrivateKey(sealed, mkey []byte) (priv []byte, err error) {
	nonce, encrypted, err := unmarshal(sealed)
	if err != nil {
		return
	}

	priv, err = cipherkit.DecryptGCM(nonce, encrypted, mkey)
	return
}

func marshal(nonce []byte, encrypted []byte) []byte {
	buf := make([]byte, 0, len(sealHeader)+len(nonce)+len(encrypted))
	buf = append(buf, sealHeader...)
	buf = append(buf, nonce...)
	buf = append(buf, encrypted...)
	return buf
}

func unmarshal(sealed []byte) (nonce, encrypted []byte, err error) {
	hlen := len(sealHeader)

	if len(sealed) < hlen {
		err = errors.New("unmarshal: too short")
		return
	}
	if !bytes.Equal(sealed[:hlen], sealHeader) {
		err = errors.New("unmarshal: invalid header")
		return
	}
	if len(sealed) < hlen+cipherkit.GCMNonceSize {
		err = errors.New("unmarshal: too short for nonce")
		return
	}

	nonce = sealed[hlen : hlen+cipherkit.GCMNonceSize]
	encrypted = sealed[hlen+cipherkit.GCMNonceSize:]
	return
}
