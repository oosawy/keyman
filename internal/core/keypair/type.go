package keypair

type EncodedPrivateKey []byte
type EncodedPublicKey []byte
type EncodedFingerprint []byte
type EncodedKeyPair struct {
	PrivateKey  EncodedPrivateKey
	PublicKey   EncodedPublicKey
	Fingerprint EncodedFingerprint
}

type messageBytes []byte
type signatureBytes []byte
