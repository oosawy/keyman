package keypair

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/x509"
	"errors"
)

func GenP256KeyPair() (*ecdsa.PrivateKey, error) {
	priv, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return nil, err
	}

	return priv, nil
}

func EncodeP256KeyPair(key *ecdsa.PrivateKey) (priv, pub, fp []byte, err error) {
	priv, err = x509.MarshalPKCS8PrivateKey(key)
	if err != nil {
		return
	}

	pub, err = x509.MarshalPKIXPublicKey(&key.PublicKey)
	if err != nil {
		return
	}

	h := sha256.New()
	h.Write(pub)
	fp = h.Sum(nil)

	return
}

func DecodeP256PrivateKey(der []byte) (*ecdsa.PrivateKey, error) {
	parsed, err := x509.ParsePKCS8PrivateKey(der)
	if err != nil {
		return nil, err
	}

	key, ok := parsed.(*ecdsa.PrivateKey)
	if !ok {
		err = errors.New("not an ECDSA private key")
		return nil, err
	}

	return key, nil
}

func Fingerprint(der []byte) []byte {
	h := sha256.New()
	h.Write(der)
	fp := h.Sum(nil)
	return fp
}
