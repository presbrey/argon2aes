package argon2aes

import (
	"bytes"
	"os"
	"testing"
)

func TestEncryptDecryptFile(t *testing.T) {
	inputFile := "testinput.txt"
	encryptedFile := "testencrypted.bin"
	decryptedFile := "testdecrypted.txt"
	password := []byte("testpassword")
	testData := []byte("This is a test file content.")

	// Create a test file
	if err := os.WriteFile(inputFile, testData, 0644); err != nil {
		t.Fatalf("Failed to create test input file: %v", err)
	}
	defer os.Remove(inputFile)

	// Encrypt the file
	if err := EncryptFile(inputFile, encryptedFile, password); err != nil {
		t.Fatalf("EncryptFile failed: %v", err)
	}
	defer os.Remove(encryptedFile)

	// Decrypt the file
	if err := DecryptFile(encryptedFile, decryptedFile, password); err != nil {
		t.Fatalf("DecryptFile failed: %v", err)
	}
	defer os.Remove(decryptedFile)

	// Read and compare the decrypted content
	decryptedContent, err := os.ReadFile(decryptedFile)
	if err != nil {
		t.Fatalf("Failed to read decrypted file: %v", err)
	}

	if !bytes.Equal(testData, decryptedContent) {
		t.Errorf("Decrypted file content doesn't match original. Original: %v, Decrypted: %v", testData, decryptedContent)
	}
}

func TestEncryptDecryptNonExistentFile(t *testing.T) {
	nonExistentFile := "nonexistent.txt"
	outputFile := "output.bin"
	password := []byte("password")

	// Try to encrypt a non-existent file
	err := EncryptFile(nonExistentFile, outputFile, password)
	if err == nil {
		t.Error("Expected an error when encrypting a non-existent file, but got none")
	}

	// Try to decrypt a non-existent file
	err = DecryptFile(nonExistentFile, outputFile, password)
	if err == nil {
		t.Error("Expected an error when decrypting a non-existent file, but got none")
	}
}

func TestEncryptDecryptWithBlankKey(t *testing.T) {
	inputFile := "testinput.txt"
	encryptedFile := "testencrypted.bin"
	decryptedFile := "testdecrypted.txt"
	blankPassword := []byte("")
	testData := []byte("This is a test file content.")

	// Create a test file
	if err := os.WriteFile(inputFile, testData, 0644); err != nil {
		t.Fatalf("Failed to create test input file: %v", err)
	}
	defer os.Remove(inputFile)

	// Try to encrypt with a blank password
	err := EncryptFile(inputFile, encryptedFile, blankPassword)
	if err == nil {
		t.Error("Expected an error when encrypting with a blank password, but got none")
		defer os.Remove(encryptedFile)
	}

	// Create an encrypted file with a non-blank password for decryption test
	validPassword := []byte("validpassword")
	if err := EncryptFile(inputFile, encryptedFile, validPassword); err != nil {
		t.Fatalf("Failed to create encrypted file for decryption test: %v", err)
	}
	defer os.Remove(encryptedFile)

	// Try to decrypt with a blank password
	err = DecryptFile(encryptedFile, decryptedFile, blankPassword)
	if err == nil {
		t.Error("Expected an error when decrypting with a blank password, but got none")
		defer os.Remove(decryptedFile)
	}
	defer os.Remove(decryptedFile)
}

func TestEncryptDecryptNoPermission(t *testing.T) {
	inputFile := "testinput.txt"
	noPermissionFile := "\000"
	password := []byte("testpassword")
	testData := []byte("This is a test file content.")

	// Create a test file
	if err := os.WriteFile(inputFile, testData, 0644); err != nil {
		t.Fatalf("Failed to create test input file: %v", err)
	}
	defer os.Remove(inputFile)

	// Try to encrypt to a file without write permission
	err := EncryptFile(inputFile, noPermissionFile, password)
	if err == nil {
		t.Error("Expected an error when encrypting to a file without write permission, but got none")
	}

	// Try to decrypt to a file without write permission
	err = DecryptFile(inputFile, noPermissionFile, password)
	if err == nil {
		t.Error("Expected an error when decrypting to a file without write permission, but got none")
	}
}
