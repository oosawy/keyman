package seal

import (
	"errors"

	"github.com/oosawy/keyman/internal/cipherkit"
)

func SealPrivateKey(priv, mkey []byte) (sealed []byte, err error) {
	nonce, encrypted, err := cipherkit.EncryptGCM(priv, mkey)
	if err != nil {
		return nil, err
	}

	sealed = marshal(nonce, encrypted)
	return
}

func UnsealPrivateKey(sealed, mkey []byte) (priv []byte, err error) {
	nonce, encrypted, err := unmarshal(sealed)
	if err != nil {
		return nil, err
	}

	priv, err = cipherkit.DecryptGCM(nonce, encrypted, mkey)
	return
}

func marshal(nonce []byte, encrypted []byte) []byte {
	buf := make([]byte, 0, len(nonce)+len(encrypted))
	buf = append(buf, nonce...)
	buf = append(buf, encrypted...)
	return buf
}

func unmarshal(sealed []byte) (nonce, encrypted []byte, err error) {
	if len(sealed) < cipherkit.GCMNonceSize {
		err = errors.New("unmarshal: too short for nonce")
		return
	}

	nonce = sealed[:cipherkit.GCMNonceSize]
	encrypted = sealed[cipherkit.GCMNonceSize:]
	return
}
