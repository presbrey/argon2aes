package argon2aes

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"fmt"

	"golang.org/x/crypto/argon2"
)

const (
	saltLength = 32
	keyLength  = 32
	time       = 3
	memory     = 64 * 1024
	threads    = 4
)

// DeriveKey generates an Argon2 key from a password and salt
func DeriveKey(password []byte, salt []byte) []byte {
	return argon2.IDKey(password, salt, time, memory, threads, keyLength)
}

// Encrypt encrypts plaintext using AES-GCM with an Argon2 key
func Encrypt(plaintext []byte, password []byte) ([]byte, error) {
	if len(password) == 0 {
		return nil, fmt.Errorf("password cannot be blank")
	}

	salt := make([]byte, saltLength)
	if _, err := rand.Read(salt); err != nil {
		return nil, err
	}

	key := DeriveKey(password, salt)

	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}

	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, err
	}

	nonce := make([]byte, gcm.NonceSize())
	if _, err := rand.Read(nonce); err != nil {
		return nil, err
	}

	ciphertext := gcm.Seal(nil, nonce, plaintext, nil)
	encrypted := make([]byte, 0, len(salt)+len(nonce)+len(ciphertext))
	encrypted = append(encrypted, salt...)
	encrypted = append(encrypted, nonce...)
	encrypted = append(encrypted, ciphertext...)

	return encrypted, nil
}

// Decrypt decrypts ciphertext using AES-GCM with an Argon2 key
func Decrypt(data []byte, password []byte) ([]byte, error) {
	if len(data) < saltLength {
		return nil, fmt.Errorf("ciphertext too short")
	}
	salt, data := data[:saltLength], data[saltLength:]

	key := DeriveKey(password, salt)

	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}

	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, err
	}

	nonceSize := gcm.NonceSize()
	if len(data) < nonceSize {
		return nil, fmt.Errorf("ciphertext too short")
	}

	nonce, ciphertext := data[:nonceSize], data[nonceSize:]
	plaintext, err := gcm.Open(nil, nonce, ciphertext, nil)
	if err != nil {
		return nil, err
	}

	return plaintext, nil
}
