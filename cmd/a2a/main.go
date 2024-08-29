package main

import (
	"encoding/base64"
	"fmt"
	"log"
	"os"

	"github.com/presbrey/argon2aes"
	"github.com/spf13/pflag"
	"golang.org/x/term"
)

func main() {
	var (
		password, key,
		inputFile, outputFile string
		passwordBytes    []byte
		encrypt, decrypt bool
		err              error
	)

	pflag.StringVarP(&key, "key", "k", "", "Encryption key (base64 encoded)")
	pflag.StringVarP(&password, "passphrase", "p", "", "Encryption passphrase")
	pflag.StringVarP(&inputFile, "in", "i", "-", "Input file (default: stdin)")
	pflag.StringVarP(&outputFile, "out", "o", "-", "Output file (default: stdout)")
	pflag.BoolVarP(&encrypt, "encrypt", "e", false, "Encrypt mode")
	pflag.BoolVarP(&decrypt, "decrypt", "d", false, "Decrypt mode")
	pflag.Parse()

	if encrypt == decrypt {
		pflag.Usage()
		os.Exit(1)
	}

	if key != "" {
		passwordBytes, err = base64.StdEncoding.DecodeString(key)
		if err != nil {
			log.Println("Invalid key. Must be base64 encoded.")
			os.Exit(1)
		}
	} else if password != "" {
		passwordBytes = []byte(password)
	} else {
		fmt.Print("Enter passphrase: ")
		passwordBytes, err = term.ReadPassword(int(os.Stdin.Fd()))
		if err != nil {
			log.Fatalf("Error reading passphrase: %v", err)
		}
		fmt.Println() // Print a newline after the password input
	}

	if len(passwordBytes) == 0 {
		log.Fatalf("Passphrase cannot be empty")
	}

	if encrypt {
		err = argon2aes.EncryptFile(inputFile, outputFile, passwordBytes)
	} else {
		err = argon2aes.DecryptFile(inputFile, outputFile, passwordBytes)
	}

	if err != nil {
		log.Printf("Error: %v\n", err)
		os.Exit(1)
	}
}
