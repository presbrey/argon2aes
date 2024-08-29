package main

import (
	"encoding/base64"
	"fmt"
	"io"
	"log"
	"os"
	"strings"

	"github.com/presbrey/argon2aes"
	"github.com/spf13/pflag"
	"golang.org/x/term"
)

var (
	passphrase, key,
	inputFile, outputFile string
	passphraseBytes                []byte
	flagEncrypt, flagDecrypt       bool
	useBase64, useBase92, useURL64 bool
)

func init() {
	pflag.StringVarP(&key, "key", "k", "", "Encryption key (base64 encoded)")
	pflag.StringVarP(&passphrase, "passphrase", "p", "", "Encryption passphrase")
	pflag.StringVarP(&inputFile, "in", "i", "-", "Input file (default: stdin)")
	pflag.StringVarP(&outputFile, "out", "o", "-", "Output file (default: stdout)")
	pflag.BoolVarP(&flagEncrypt, "encrypt", "e", false, "Encrypt mode")
	pflag.BoolVarP(&flagDecrypt, "decrypt", "d", false, "Decrypt mode")
	pflag.BoolVarP(&useBase64, "base64", "6", false, "Use standard base64 encoding for input/output")
	pflag.BoolVarP(&useBase92, "base92", "9", false, "Use base92 encoding for input/output")
	pflag.BoolVarP(&useURL64, "url64", "u", false, "Use URL-safe base64 encoding for input/output")
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

	if flagEncrypt == flagDecrypt {
		pflag.Usage()
		return fmt.Errorf("must specify either encrypt or decrypt mode")
	}

	if (useBase64 && useBase92) || (useBase64 && useURL64) || (useBase92 && useURL64) {
		return fmt.Errorf("can only use one encoding option: base64, url64, or base92")
	}

	if key != "" {
		var encoding *base64.Encoding
		if strings.ContainsAny(key, "-_") {
			encoding = base64.URLEncoding
		} else {
			encoding = base64.StdEncoding
		}
		passphraseBytes, err = encoding.DecodeString(key)
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

	if flagEncrypt {
		err = encryptWithEncoding(inputFile, outputFile, passphraseBytes)
	} else {
		err = decryptWithEncoding(inputFile, outputFile, passphraseBytes)
	}

	return err
}

func encryptWithEncoding(inputFile, outputFile string, passphrase []byte) error {
	input, err := readInput(inputFile)
	if err != nil {
		return err
	}

	encrypted, err := argon2aes.Encrypt(input, passphrase)
	if err != nil {
		return err
	}

	return writeOutput(outputFile, encrypted)
}

func decryptWithEncoding(inputFile, outputFile string, passphrase []byte) error {
	input, err := readInput(inputFile)
	if err != nil {
		return err
	}

	decrypted, err := argon2aes.Decrypt(input, passphrase)
	if err != nil {
		return err
	}

	return writeOutput(outputFile, decrypted)
}

func readInput(inputFile string) ([]byte, error) {
	var input []byte
	var err error

	if inputFile == "-" {
		input, err = io.ReadAll(os.Stdin)
	} else {
		input, err = os.ReadFile(inputFile)
	}

	if err != nil {
		return nil, err
	}

	if flagDecrypt {
		if useBase64 {
			return base64.StdEncoding.DecodeString(string(input))
		} else if useURL64 {
			return base64.URLEncoding.DecodeString(string(input))
		} else if useBase92 {
			return base92decode(string(input))
		}
	}

	return input, nil
}

func writeOutput(outputFile string, data []byte) error {
	var output []byte

	if flagEncrypt {
		if useBase64 {
			output = []byte(base64.RawStdEncoding.EncodeToString(data))
		} else if useURL64 {
			output = []byte(base64.RawURLEncoding.EncodeToString(data))
		} else if useBase92 {
			output = []byte(base92encode(data))
		} else {
			output = data
		}
	} else {
		output = data
	}

	if outputFile == "-" {
		_, err := os.Stdout.Write(output)
		return err
	}

	return os.WriteFile(outputFile, output, 0644)
}
