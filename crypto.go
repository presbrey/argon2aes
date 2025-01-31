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

	var (
		err error

		block cipher.Block
		gcm   cipher.AEAD
		nonce []byte
	)
	if block, err = aes.NewCipher(key); err == nil {
		if gcm, err = cipher.NewGCM(block); err == nil {
			nonce = make([]byte, gcm.NonceSize())
			if _, err = rand.Read(nonce); err == nil {
				ciphertext := gcm.Seal(nil, nonce, plaintext, nil)
				encrypted := make([]byte, 0, len(salt)+len(nonce)+len(ciphertext))
				encrypted = append(encrypted, salt...)
				encrypted = append(encrypted, nonce...)
				encrypted = append(encrypted, ciphertext...)
				return encrypted, nil
			}
		}
	}
	return nil, err
}

// Decrypt decrypts ciphertext using AES-GCM with an Argon2 key
func Decrypt(data []byte, password []byte) ([]byte, error) {
	if len(data) < saltLength {
		return nil, fmt.Errorf("ciphertext too short")
	}
	salt, data := data[:saltLength], data[saltLength:]

	key := DeriveKey(password, salt)

	var (
		err error

		block cipher.Block
		gcm   cipher.AEAD
	)

	if block, err = aes.NewCipher(key); err == nil {
		if gcm, err = cipher.NewGCM(block); err == nil {
			nonceSize := gcm.NonceSize()
			if len(data) < nonceSize {
				return nil, fmt.Errorf("ciphertext too short")
			}

			nonce, ciphertext := data[:nonceSize], data[nonceSize:]
			var plaintext []byte
			if plaintext, err = gcm.Open(nil, nonce, ciphertext, nil); err == nil {
				return plaintext, nil
			}
		}
	}
	return nil, err
}
