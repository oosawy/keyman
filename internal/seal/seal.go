package seal

import (
	"errors"

	"github.com/oosawy/keyman/internal/cipherkit"
	"github.com/oosawy/keyman/internal/keypair"
)

func SealPrivateKey(priv keypair.EncodedPrivateKey, mkey cipherkit.MasterKey) (SealedPrivateKey, error) {
	nonce, encrypted, err := cipherkit.EncryptGCM(cipherkit.Plaintext(priv), mkey)
	if err != nil {
		return nil, err
	}

	sealed := marshal(nonce, encrypted)
	return sealed, nil
}

func UnsealPrivateKey(sealed SealedPrivateKey, mkey cipherkit.MasterKey) (keypair.EncodedPrivateKey, error) {
	nonce, encrypted, err := unmarshal(sealed)
	if err != nil {
		return nil, err
	}

	plain, err := cipherkit.DecryptGCM(nonce, encrypted, mkey)
	if err != nil {
		return nil, err
	}

	priv := keypair.EncodedPrivateKey(plain)
	return priv, nil
}

func marshal(nonce cipherkit.Nonce, encrypted cipherkit.Ciphertext) SealedPrivateKey {
	buf := make([]byte, 0, len(nonce)+len(encrypted))
	buf = append(buf, nonce...)
	buf = append(buf, encrypted...)
	return buf
}

func unmarshal(sealed SealedPrivateKey) (cipherkit.Nonce, cipherkit.Ciphertext, error) {
	if len(sealed) < cipherkit.GCMNonceSize {
		err := errors.New("unmarshal: too short for nonce")
		return nil, nil, err
	}

	nonce := cipherkit.Nonce(sealed[:cipherkit.GCMNonceSize])
	encrypted := cipherkit.Ciphertext(sealed[cipherkit.GCMNonceSize:])
	return nonce, encrypted, nil
}
