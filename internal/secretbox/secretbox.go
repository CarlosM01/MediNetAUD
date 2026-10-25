// Package secretbox encrypts small secrets with AES-256-GCM.
package secretbox

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"encoding/base64"
	"errors"
	"fmt"
)

// KeySize is the AES-256 key length in bytes.
const KeySize = 32

// ErrDecrypt means the ciphertext was altered, sealed with another key or bound to other data.
var ErrDecrypt = errors.New("secretbox: decryption failed")

// Box seals and opens secrets with one key.
type Box struct {
	aead cipher.AEAD
}

// ParseKey decodes a standard base64 key of KeySize bytes.
func ParseKey(s string) ([]byte, error) {
	key, err := base64.StdEncoding.DecodeString(s)
	if err != nil {
		return nil, fmt.Errorf("secretbox: key is not valid base64: %w", err)
	}
	if len(key) != KeySize {
		return nil, fmt.Errorf("secretbox: key must be %d bytes, got %d", KeySize, len(key))
	}
	return key, nil
}

// New returns a Box for a KeySize-byte key.
func New(key []byte) (*Box, error) {
	if len(key) != KeySize {
		return nil, fmt.Errorf("secretbox: key must be %d bytes, got %d", KeySize, len(key))
	}
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}
	aead, err := cipher.NewGCM(block)
	if err != nil {
		return nil, err
	}
	return &Box{aead: aead}, nil
}

// Seal encrypts plaintext and returns nonce || ciphertext || tag. The additional data is
// authenticated but not stored, so the result can only be opened with the same value.
func (b *Box) Seal(plaintext, additionalData []byte) ([]byte, error) {
	nonce := make([]byte, b.aead.NonceSize(), b.aead.NonceSize()+len(plaintext)+b.aead.Overhead())
	if _, err := rand.Read(nonce); err != nil {
		return nil, err
	}
	return b.aead.Seal(nonce, nonce, plaintext, additionalData), nil
}

// Open decrypts a value produced by Seal with the same additional data.
func (b *Box) Open(sealed, additionalData []byte) ([]byte, error) {
	n := b.aead.NonceSize()
	if len(sealed) < n+b.aead.Overhead() {
		return nil, ErrDecrypt
	}
	plaintext, err := b.aead.Open(nil, sealed[:n], sealed[n:], additionalData)
	if err != nil {
		return nil, ErrDecrypt
	}
	return plaintext, nil
}
