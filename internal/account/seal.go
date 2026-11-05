package account

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/hkdf"
	"crypto/rand"
	"crypto/sha256"
	"errors"
)

// sealKey derives a key for one purpose from AUTH_SECRET, so one secret keys
// several things without reusing a key.
func (s *Service) sealKey(purpose string) ([]byte, error) {
	return hkdf.Key(sha256.New, s.secret, nil, "renora "+purpose, 32)
}

// seal encrypts a secret that must be read back (an authenticator secret),
// with AES-256-GCM. The output is nonce || ciphertext.
func (s *Service) seal(purpose string, plain []byte) ([]byte, error) {
	aead, err := s.aead(purpose)
	if err != nil {
		return nil, err
	}
	nonce := make([]byte, aead.NonceSize())
	_, _ = rand.Read(nonce)
	return aead.Seal(nonce, nonce, plain, []byte(purpose)), nil
}

func (s *Service) open(purpose string, sealed []byte) ([]byte, error) {
	aead, err := s.aead(purpose)
	if err != nil {
		return nil, err
	}
	if len(sealed) < aead.NonceSize() {
		return nil, errors.New("sealed value too short")
	}
	n := aead.NonceSize()
	return aead.Open(nil, sealed[:n], sealed[n:], []byte(purpose))
}

func (s *Service) aead(purpose string) (cipher.AEAD, error) {
	key, err := s.sealKey(purpose)
	if err != nil {
		return nil, err
	}
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}
	return cipher.NewGCM(block)
}
