package main

import (
	"encoding/base64"
	"log"
	"os"

	"github.com/presbrey/argon2aes"
	"github.com/spf13/pflag"
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
	pflag.StringVarP(&password, "password", "p", "", "Encryption password (raw)")
	pflag.StringVarP(&inputFile, "in", "i", "", "Input file path")
	pflag.StringVarP(&outputFile, "out", "o", "", "Output file path")
	pflag.BoolVarP(&encrypt, "encrypt", "e", false, "Encrypt the input file")
	pflag.BoolVarP(&decrypt, "decrypt", "d", false, "Decrypt the input file")
	pflag.Parse()

	if (password == "" && key == "") || inputFile == "" || outputFile == "" || (encrypt == decrypt) {
		pflag.Usage()
		os.Exit(1)
	}

	if key != "" {
		passwordBytes, err = base64.StdEncoding.DecodeString(key)
		if err != nil {
			log.Println("Invalid key. Must be base64 encoded.")
			os.Exit(1)
		}
	} else {
		passwordBytes = []byte(password)
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
