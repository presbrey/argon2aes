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

var (
	passphrase, key,
	inputFile, outputFile string
	passphraseBytes  []byte
	encrypt, decrypt bool
)

func init() {
	pflag.StringVarP(&key, "key", "k", "", "Encryption key (base64 encoded)")
	pflag.StringVarP(&passphrase, "passphrase", "p", "", "Encryption passphrase")
	pflag.StringVarP(&inputFile, "in", "i", "-", "Input file (default: stdin)")
	pflag.StringVarP(&outputFile, "out", "o", "-", "Output file (default: stdout)")
	pflag.BoolVarP(&encrypt, "encrypt", "e", false, "Encrypt mode")
	pflag.BoolVarP(&decrypt, "decrypt", "d", false, "Decrypt mode")
	pflag.Parse()
}

func main() {
	if err := run(); err != nil {
		log.Printf("Error: %v\n", err)
		os.Exit(1)
	}
}

func run() error {
	var err error

	if encrypt == decrypt {
		pflag.Usage()
		return fmt.Errorf("must specify either encrypt or decrypt mode")
	}

	if key != "" {
		passphraseBytes, err = base64.StdEncoding.DecodeString(key)
		if err != nil {
			return fmt.Errorf("invalid key. Must be base64 encoded")
		}
	} else if passphrase != "" {
		passphraseBytes = []byte(passphrase)
	} else {
		fmt.Print("Enter passphrase: ")
		passphraseBytes, err = term.ReadPassword(int(os.Stdin.Fd()))
		if err != nil {
			return fmt.Errorf("error reading passphrase: %v", err)
		}
		fmt.Println() // Print a newline after the password input
	}

	if len(passphraseBytes) == 0 {
		return fmt.Errorf("passphrase cannot be empty")
	}

	if encrypt {
		err = argon2aes.EncryptFile(inputFile, outputFile, passphraseBytes)
	} else {
		err = argon2aes.DecryptFile(inputFile, outputFile, passphraseBytes)
	}

	return err
}
