package argon2aes

import (
	"bytes"
	"testing"
)

func TestEncryptDecrypt(t *testing.T) {
	testCases := []struct {
		name     string
		data     []byte
		password []byte
	}{
		{"Empty", []byte{}, []byte("password")},
		{"Short", []byte("Hello, World!"), []byte("password")},
		{"Long", bytes.Repeat([]byte("A"), 1000), []byte("password")},
		{"Unicode", []byte("Hello, 世界!"), []byte("password")},
		{"Binary", []byte{0, 1, 2, 3, 4, 5}, []byte("password")},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			encrypted, err := Encrypt(tc.data, tc.password)
			if err != nil {
				t.Fatalf("Encrypt failed: %v", err)
			}

			decrypted, err := Decrypt(encrypted, tc.password)
			if err != nil {
				t.Fatalf("Decrypt failed: %v", err)
			}

			if !bytes.Equal(tc.data, decrypted) {
				t.Errorf("Decrypted data doesn't match original. Original: %v, Decrypted: %v", tc.data, decrypted)
			}
		})
	}
}

func TestDecryptWithWrongPassword(t *testing.T) {
	data := []byte("Secret message")
	password := []byte("correct password")
	wrongPassword := []byte("wrong password")

	encrypted, err := Encrypt(data, password)
	if err != nil {
		t.Fatalf("Encrypt failed: %v", err)
	}

	_, err = Decrypt(encrypted, wrongPassword)
	if err == nil {
		t.Error("Expected an error when decrypting with wrong password, but got none")
	}
}

func TestDeriveKey(t *testing.T) {
	password := []byte("password")
	salt := []byte("saltsaltsaltsalt") // 16 bytes

	key1 := DeriveKey(password, salt)
	key2 := DeriveKey(password, salt)

	if !bytes.Equal(key1, key2) {
		t.Error("DeriveKey is not deterministic")
	}

	if len(key1) != keyLength {
		t.Errorf("Expected key length %d, got %d", keyLength, len(key1))
	}
}

func TestDecryptShortCiphertext(t *testing.T) {
	testCases := []struct {
		name        string
		ciphertext  []byte
		expectedErr string
	}{
		{"Empty", []byte{}, "ciphertext too short"},
		{"TooShort", []byte("tooshort"), "ciphertext too short"},
		{"JustSalt", make([]byte, saltLength), "ciphertext too short"},
		{"SaltPlusShort", append(make([]byte, saltLength), []byte("short")...), "ciphertext too short"},
	}

	password := []byte("password")

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			_, err := Decrypt(tc.ciphertext, password)
			if err == nil {
				t.Error("Expected an error when decrypting short ciphertext, but got none")
			} else if err.Error() != tc.expectedErr {
				t.Errorf("Expected error '%s', but got '%s'", tc.expectedErr, err.Error())
			}
		})
	}
}
