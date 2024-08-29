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
		os.Args = []string{"a2a", "-e", "-i", inFile, "-o", outFile, "-p", string(password)}

		// Run main
		main()

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
		os.Args = []string{"a2a", "-d", "-i", inFile, "-o", outFile, "-p", string(password)}

		// Run main
		main()

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
		os.Args = []string{"a2a", "-e", "-d"}

		// Run main
		main()

		// Restore stdout and stderr
		w.Close()
		out, _ := ioutil.ReadAll(r)
		os.Stdout = oldStdout
		os.Stderr = oldStderr

		// Check if usage information was printed
		if !bytes.Contains(out, []byte("Usage of")) {
			t.Errorf("Usage information was not printed for invalid arguments")
		}
	})
}
