package argon2aes

import "os"

func EncryptFile(inputPath, outputPath string, password []byte) error {
	plaintext, err := os.ReadFile(inputPath)
	if err != nil {
		return err
	}

	ciphertext, err := Encrypt(plaintext, password)
	if err != nil {
		return err
	}

	return os.WriteFile(outputPath, ciphertext, 0644)
}

func DecryptFile(inputPath, outputPath string, password []byte) error {
	ciphertext, err := os.ReadFile(inputPath)
	if err != nil {
		return err
	}

	plaintext, err := Decrypt(ciphertext, password)
	if err != nil {
		return err
	}

	return os.WriteFile(outputPath, plaintext, 0644)
}
