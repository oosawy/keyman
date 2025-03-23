package keygen

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/x509"
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
