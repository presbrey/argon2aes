package main

import (
	"bytes"
	"io/ioutil"
	"os"
	"path/filepath"
	"testing"
)

func TestMain(t *testing.T) {
	// Create a temporary directory for test files
	tempDir, err := ioutil.TempDir("", "a2a_test")
	if err != nil {
		t.Fatalf("Failed to create temp dir: %v", err)
	}
	defer os.RemoveAll(tempDir)

	// Test data
	plaintext := []byte("Hello, World!")
	password := []byte("testpassword")

	// Test encryption
	t.Run("Encrypt", func(t *testing.T) {
		inFile := filepath.Join(tempDir, "input.txt")
		outFile := filepath.Join(tempDir, "encrypted.bin")

		err := ioutil.WriteFile(inFile, plaintext, 0644)
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
		encrypt = true
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
		encrypt = false
		decrypt = true
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
		decrypted, err := ioutil.ReadFile(outFile)
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
		encrypt = true
		decrypt = true

		// Run the command
		err := run()

		// Restore stdout and stderr
		w.Close()
		out, _ := ioutil.ReadAll(r)
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

		err := ioutil.WriteFile(inFile, plaintext, 0644)
		if err != nil {
			t.Fatalf("Failed to write input file: %v", err)
		}

		// Generate a base64 encoded key
		base64Key := "YWJjMTIzIT8kKiYoKSctPUB+"

		// Encrypt with base64 key
		encrypt = true
		decrypt = false
		inputFile = inFile
		outputFile = outFile
		key = base64Key
		passphrase = ""

		err = run()
		if err != nil {
			t.Fatalf("Failed to run encryption with base64 key: %v", err)
		}

		// Decrypt with base64 key
		encrypt = false
		decrypt = true
		inputFile = outFile
		outputFile = decryptedFile
		key = base64Key
		passphrase = ""

		err = run()
		if err != nil {
			t.Fatalf("Failed to run decryption with base64 key: %v", err)
		}

		// Read the decrypted file
		decrypted, err := ioutil.ReadFile(decryptedFile)
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

		err := ioutil.WriteFile(inFile, plaintext, 0644)
		if err != nil {
			t.Fatalf("Failed to write input file: %v", err)
		}

		// Generate a URL-safe base64 encoded key
		urlSafeKey := "YWJjMTIzIT8kKiYoKSctPUB-"

		// Encrypt with URL-safe base64 key
		encrypt = true
		decrypt = false
		inputFile = inFile
		outputFile = outFile
		key = urlSafeKey
		passphrase = ""

		err = run()
		if err != nil {
			t.Fatalf("Failed to run encryption with URL-safe base64 key: %v", err)
		}

		// Decrypt with URL-safe base64 key
		encrypt = false
		decrypt = true
		inputFile = outFile
		outputFile = decryptedFile
		key = urlSafeKey
		passphrase = ""

		err = run()
		if err != nil {
			t.Fatalf("Failed to run decryption with URL-safe base64 key: %v", err)
		}

		// Read the decrypted file
		decrypted, err := ioutil.ReadFile(decryptedFile)
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

		err := ioutil.WriteFile(inFile, plaintext, 0644)
		if err != nil {
			t.Fatalf("Failed to write input file: %v", err)
		}

		// Set an invalid base64 key
		invalidKey := "this is not a valid base64 key"

		// Try to encrypt with invalid key
		encrypt = true
		decrypt = false
		inputFile = inFile
		outputFile = outFile
		key = invalidKey
		passphrase = ""

		err = run()
		if err == nil {
			t.Errorf("Expected an error when encrypting with invalid key, but got none")
		}

		// Try to decrypt with invalid key
		encrypt = false
		decrypt = true
		inputFile = outFile
		outputFile = filepath.Join(tempDir, "decrypted_invalid.txt")

		err = run()
		if err == nil {
			t.Errorf("Expected an error when decrypting with invalid key, but got none")
		}
	})
}
