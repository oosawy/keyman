package main

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"encoding/hex"
	"fmt"
	"io"
	"os"
)

func getKey() ([]byte, error) {
	keyHex := os.Getenv("AES_KEY_HEX")
	key, err := hex.DecodeString(keyHex)
	if err != nil {
		return nil, fmt.Errorf("invalid key hex: %w", err)
	}
	if len(key) != 32 {
		return nil, fmt.Errorf("key must be 32 bytes for AES-256-GCM")
	}
	return key, nil
}

func encryptGCM(plainText string, key []byte) ([]byte, []byte, error) {
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, nil, err
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, nil, err
	}

	nonce := make([]byte, gcm.NonceSize())
	if _, err := io.ReadFull(rand.Reader, nonce); err != nil {
		return nil, nil, err
	}

	cipherText := gcm.Seal(nil, nonce, []byte(plainText), nil)
	return nonce, cipherText, nil
}

func decryptGCM(nonce, cipherText, key []byte) (string, error) {
	block, err := aes.NewCipher(key)
	if err != nil {
		return "", err
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return "", err
	}
	plain, err := gcm.Open(nil, nonce, cipherText, nil)
	if err != nil {
		return "", err
	}
	return string(plain), nil
}

func main() {
	key, err := getKey()
	if err != nil {
		panic(err)
	}

	original := "Hello, AES-GCM!"
	fmt.Println("Original:", original)

	nonce, encrypted, err := encryptGCM(original, key)
	if err != nil {
		panic(err)
	}
	fmt.Printf("Nonce    (hex): %s\n", hex.EncodeToString(nonce))
	fmt.Printf("Encrypted(hex): %s\n", hex.EncodeToString(encrypted))

	decrypted, err := decryptGCM(nonce, encrypted, key)
	if err != nil {
		panic(err)
	}
	fmt.Println("Decrypted:", decrypted)
}
