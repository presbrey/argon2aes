package main

import (
	"bytes"
	"encoding/base64"
	"io"
	"os"
	"path/filepath"
	"testing"
)

func TestMain(t *testing.T) {
	// Create a temporary directory for test files
	tempDir, err := os.MkdirTemp("", "a2a_test")
	if err != nil {
		t.Fatalf("Failed to create temp dir: %v", err)
	}
	defer os.RemoveAll(tempDir)

	// Test data
	plaintext := []byte("Hello, World!")
	password := []byte("YWJjMTIzIT8kKiYoKSctPUB+")

	// Test encryption
	t.Run("Encrypt", func(t *testing.T) {
		inFile := filepath.Join(tempDir, "input.txt")
		outFile := filepath.Join(tempDir, "encrypted.bin")

		err := os.WriteFile(inFile, plaintext, 0644)
		if err != nil {
			t.Fatalf("Failed to write input file: %v", err)
		}

		// Redirect stdout and stderr
		oldStdout := os.Stdout
		oldStderr := os.Stderr
		_, w, _ := os.Pipe()
		os.Stdout = w
		os.Stderr = w

		// Set command-line arguments
		flagEncrypt = true
		inputFile = inFile
		outputFile = outFile
		passphrase = string(password)

		// Run the command
		err = run()
		if err != nil {
			t.Fatalf("Failed to run command: %v", err)
		}

		// Restore stdout and stderr
		w.Close()
		os.Stdout = oldStdout
		os.Stderr = oldStderr

		// Check if the output file exists
		if _, err := os.Stat(outFile); os.IsNotExist(err) {
			t.Errorf("Output file was not created")
		}
	})

	// Test decryption
	t.Run("Decrypt", func(t *testing.T) {
		inFile := filepath.Join(tempDir, "encrypted.bin")
		outFile := filepath.Join(tempDir, "decrypted.txt")

		// Redirect stdout and stderr
		oldStdout := os.Stdout
		oldStderr := os.Stderr
		_, w, _ := os.Pipe()
		os.Stdout = w
		os.Stderr = w

		// Set command-line arguments
		flagEncrypt = false
		flagDecrypt = true
		inputFile = inFile
		outputFile = outFile
		passphrase = string(password)

		// Run the command
		err = run()
		if err != nil {
			t.Fatalf("Failed to run command: %v", err)
		}

		// Restore stdout and stderr
		w.Close()
		os.Stdout = oldStdout
		os.Stderr = oldStderr

		// Read the decrypted file
		decrypted, err := os.ReadFile(outFile)
		if err != nil {
			t.Fatalf("Failed to read decrypted file: %v", err)
		}

		// Compare the decrypted content with the original plaintext
		if !bytes.Equal(decrypted, plaintext) {
			t.Errorf("Decrypted content does not match original. Got %s, want %s", decrypted, plaintext)
		}
	})

	// Test invalid arguments
	t.Run("InvalidArgs", func(t *testing.T) {
		// Redirect stdout and stderr
		oldStdout := os.Stdout
		oldStderr := os.Stderr
		r, w, _ := os.Pipe()
		os.Stdout = w
		os.Stderr = w

		// Set invalid command-line arguments (both encrypt and decrypt)
		flagEncrypt = true
		flagDecrypt = true

		// Run the command
		err := run()

		// Restore stdout and stderr
		w.Close()
		out, _ := io.ReadAll(r)
		os.Stdout = oldStdout
		os.Stderr = oldStderr

		// Check if an error was returned
		if err == nil {
			t.Errorf("Expected an error for invalid arguments, but got none")
		}

		// Check if usage information was printed
		if !bytes.Contains(out, []byte("Usage of")) {
			t.Errorf("Usage information was not printed for invalid arguments")
		}
	})

	// Test base64 key
	t.Run("Base64Key", func(t *testing.T) {
		inFile := filepath.Join(tempDir, "input.txt")
		outFile := filepath.Join(tempDir, "encrypted_base64.bin")
		decryptedFile := filepath.Join(tempDir, "decrypted_base64.txt")

		err := os.WriteFile(inFile, plaintext, 0644)
		if err != nil {
			t.Fatalf("Failed to write input file: %v", err)
		}

		// Generate a base64 encoded key
		base64Key := "YWJjMTIzIT8kKiYoKSctPUB+"

		// Encrypt with base64 key
		flagEncrypt = true
		flagDecrypt = false
		inputFile = inFile
		outputFile = outFile
		key = base64Key
		passphrase = ""

		err = run()
		if err != nil {
			t.Fatalf("Failed to run encryption with base64 key: %v", err)
		}

		// Decrypt with base64 key
		flagEncrypt = false
		flagDecrypt = true
		inputFile = outFile
		outputFile = decryptedFile
		key = base64Key
		passphrase = ""

		err = run()
		if err != nil {
			t.Fatalf("Failed to run decryption with base64 key: %v", err)
		}

		// Read the decrypted file
		decrypted, err := os.ReadFile(decryptedFile)
		if err != nil {
			t.Fatalf("Failed to read decrypted file: %v", err)
		}

		// Compare the decrypted content with the original plaintext
		if !bytes.Equal(decrypted, plaintext) {
			t.Errorf("Decrypted content does not match original. Got %s, want %s", decrypted, plaintext)
		}
	})

	// Test URL-safe base64 key
	t.Run("URLSafeBase64Key", func(t *testing.T) {
		inFile := filepath.Join(tempDir, "input_urlsafe.txt")
		outFile := filepath.Join(tempDir, "encrypted_urlsafe.bin")
		decryptedFile := filepath.Join(tempDir, "decrypted_urlsafe.txt")

		err := os.WriteFile(inFile, plaintext, 0644)
		if err != nil {
			t.Fatalf("Failed to write input file: %v", err)
		}

		// Generate a URL-safe base64 encoded key
		urlSafeKey := "YWJjMTIzIT8kKiYoKSctPUB-"

		// Encrypt with URL-safe base64 key
		flagEncrypt = true
		flagDecrypt = false
		inputFile = inFile
		outputFile = outFile
		key = urlSafeKey
		passphrase = ""

		err = run()
		if err != nil {
			t.Fatalf("Failed to run encryption with URL-safe base64 key: %v", err)
		}

		// Decrypt with URL-safe base64 key
		flagEncrypt = false
		flagDecrypt = true
		inputFile = outFile
		outputFile = decryptedFile
		key = urlSafeKey
		passphrase = ""

		err = run()
		if err != nil {
			t.Fatalf("Failed to run decryption with URL-safe base64 key: %v", err)
		}

		// Read the decrypted file
		decrypted, err := os.ReadFile(decryptedFile)
		if err != nil {
			t.Fatalf("Failed to read decrypted file: %v", err)
		}

		// Compare the decrypted content with the original plaintext
		if !bytes.Equal(decrypted, plaintext) {
			t.Errorf("Decrypted content does not match original. Got %s, want %s", decrypted, plaintext)
		}
	})

	// Test invalid key
	t.Run("InvalidKey", func(t *testing.T) {
		inFile := filepath.Join(tempDir, "input_invalid.txt")
		outFile := filepath.Join(tempDir, "encrypted_invalid.bin")

		err := os.WriteFile(inFile, plaintext, 0644)
		if err != nil {
			t.Fatalf("Failed to write input file: %v", err)
		}

		// Set an invalid base64 key
		invalidKey := "this is not a valid base64 key"

		// Try to encrypt with invalid key
		flagEncrypt = true
		flagDecrypt = false
		inputFile = inFile
		outputFile = outFile
		key = invalidKey
		passphrase = ""

		err = run()
		if err == nil {
			t.Errorf("Expected an error when encrypting with invalid key, but got none")
		}

		// Try to decrypt with invalid key
		flagEncrypt = false
		flagDecrypt = true
		inputFile = outFile
		outputFile = filepath.Join(tempDir, "decrypted_invalid.txt")

		err = run()
		if err == nil {
			t.Errorf("Expected an error when decrypting with invalid key, but got none")
		}
	})

	// Test base64 encoding
	t.Run("Base64Encoding", func(t *testing.T) {
		inFile := filepath.Join(tempDir, "input_base64.txt")
		outFile := filepath.Join(tempDir, "encrypted_base64.bin")
		decryptedFile := filepath.Join(tempDir, "decrypted_base64.txt")

		base64Plaintext := base64.RawStdEncoding.EncodeToString(plaintext)
		err := os.WriteFile(inFile, []byte(base64Plaintext), 0644)
		if err != nil {
			t.Fatalf("Failed to write input file: %v", err)
		}

		// Encrypt with base64 input
		flagEncrypt = true
		flagDecrypt = false
		inputFile = inFile
		outputFile = outFile
		key = string(password)
		useBase64 = true
		useBase92 = false

		err = run()
		if err != nil {
			t.Fatalf("Failed to run encryption with base64 input: %v", err)
		}

		// Decrypt with base64 output
		flagEncrypt = false
		flagDecrypt = true
		inputFile = outFile
		outputFile = decryptedFile
		passphrase = string(password)
		useBase64 = true
		useBase92 = false

		err = run()
		if err != nil {
			t.Fatalf("Failed to run decryption with base64 output: %v", err)
		}

		// Read the decrypted file
		decrypted, err := os.ReadFile(decryptedFile)
		if err != nil {
			t.Fatalf("Failed to read decrypted file: %v", err)
		}

		// Decode base64
		decodedDecrypted, err := base64.RawStdEncoding.DecodeString(string(decrypted))
		if err != nil {
			t.Fatalf("Failed to decode base64: %v", err)
		}

		// Compare the decrypted content with the original plaintext
		if !bytes.Equal(decodedDecrypted, plaintext) {
			t.Errorf("Decrypted content does not match original. Got %s, want %s", decodedDecrypted, plaintext)
		}
	})

	// Test base92 encoding
	t.Run("Base92Encoding", func(t *testing.T) {
		inFile := filepath.Join(tempDir, "input_base92.txt")
		outFile := filepath.Join(tempDir, "encrypted_base92.bin")
		decryptedFile := filepath.Join(tempDir, "decrypted_base92.txt")

		base92Plaintext := base92encode(plaintext)
		err := os.WriteFile(inFile, []byte(base92Plaintext), 0644)
		if err != nil {
			t.Fatalf("Failed to write input file: %v", err)
		}

		// Encrypt with base92 input
		flagEncrypt = true
		flagDecrypt = false
		inputFile = inFile
		outputFile = outFile
		passphrase = string(password)
		useBase64 = false
		useBase92 = true

		err = run()
		if err != nil {
			t.Fatalf("Failed to run encryption with base92 input: %v", err)
		}

		// Decrypt with base92 output
		flagEncrypt = false
		flagDecrypt = true
		inputFile = outFile
		outputFile = decryptedFile
		passphrase = string(password)
		useBase64 = false
		useBase92 = true

		err = run()
		if err != nil {
			t.Fatalf("Failed to run decryption with base92 output: %v", err)
		}

		// Read the decrypted file
		decrypted, err := os.ReadFile(decryptedFile)
		if err != nil {
			t.Fatalf("Failed to read decrypted file: %v", err)
		}

		// Decode base92
		decodedDecrypted, err := base92decode(string(decrypted))
		if err != nil {
			t.Fatalf("Failed to decode base92: %v", err)
		}

		// Compare the decrypted content with the original plaintext
		if !bytes.Equal(decodedDecrypted, plaintext) {
			t.Errorf("Decrypted content does not match original. Got %s, want %s", decodedDecrypted, plaintext)
		}
	})
}
