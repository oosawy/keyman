package cipherkit

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"encoding/hex"
	"fmt"
	"io"
)

const GCMNonceSize = 12 /* == gcmStandardNonceSize */

func GetKeyAES(keyHex string) (MasterKey, error) {
	key, err := hex.DecodeString(keyHex)
	if err != nil {
		return nil, fmt.Errorf("invalid key hex: %w", err)
	}
	if len(key) != 32 {
		return nil, fmt.Errorf("key must be 32 bytes for AES-256-GCM")
	}
	return key, nil
}

func EncryptGCM(plaintext Plaintext, mkey MasterKey) (Nonce, Ciphertext, error) {
	if len(mkey) != 32 {
		return nil, nil, fmt.Errorf("key must be 32 bytes for AES-256-GCM")
	}

	block, err := aes.NewCipher(mkey)
	if err != nil {
		return nil, nil, err
	}
	gcm, err := cipher.NewGCMWithNonceSize(block, GCMNonceSize)
	if err != nil {
		return nil, nil, err
	}

	nonce := make([]byte, gcm.NonceSize())
	if _, err := io.ReadFull(rand.Reader, nonce); err != nil {
		return nil, nil, err
	}

	ciphertext := gcm.Seal(nil, nonce, plaintext, nil)
	return nonce, ciphertext, nil
}

func DecryptGCM(nonce Nonce, ciphertext Ciphertext, mkey MasterKey) (Plaintext, error) {
	if len(mkey) != 32 {
		panic("key must be 32 bytes for AES-256-GCM")
	}

	block, err := aes.NewCipher(mkey)
	if err != nil {
		return nil, err
	}

	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, err
	}

	plaintext, err := gcm.Open(nil, nonce, ciphertext, nil)
	if err != nil {
		return nil, err
	}

	return plaintext, nil
}
