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

func EncodeP256KeyPair(key *ecdsa.PrivateKey) (*EncodedKeyPair, error) {
	priv, err := x509.MarshalPKCS8PrivateKey(key)
	if err != nil {
		return nil, err
	}

	pub, err := x509.MarshalPKIXPublicKey(&key.PublicKey)
	if err != nil {
		return nil, err
	}

	fp := Fingerprint(pub)

	encoded := &EncodedKeyPair{
		PrivateKey:  priv,
		PublicKey:   pub,
		Fingerprint: fp,
	}

	return encoded, nil
}

func DecodeP256PrivateKey(der EncodedPrivateKey) (*ecdsa.PrivateKey, error) {
	parsed, err := x509.ParsePKCS8PrivateKey(der)
	if err != nil {
		return nil, err
	}

	key, ok := parsed.(*ecdsa.PrivateKey)
	if !ok {
		return nil, errors.New("not an ECDSA private key")
	}

	return key, nil
}

func DecodeP256PublicKey(der EncodedPublicKey) (*ecdsa.PublicKey, error) {
	pub, err := x509.ParsePKIXPublicKey(der)
	if err != nil {
		return nil, err
	}

	key, ok := pub.(*ecdsa.PublicKey)
	if !ok {
		return nil, errors.New("not an ECDSA public key")
	}

	return key, nil
}

func Fingerprint(der EncodedPublicKey) EncodedFingerprint {
	h := sha256.New()
	h.Write(der)
	fp := h.Sum(nil)
	return fp
}

func Sign(priv *ecdsa.PrivateKey, message messageBytes) (signatureBytes, error) {
	hash := sha256.Sum256(message)
	return ecdsa.SignASN1(rand.Reader, priv, hash[:])
}

func Verify(pub *ecdsa.PublicKey, message messageBytes, sig signatureBytes) bool {
	hash := sha256.Sum256(message)
	return ecdsa.VerifyASN1(pub, hash[:], sig)
}
