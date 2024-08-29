package argon2aes

import (
	"io"
	"os"
)

func EncryptFile(inputPath, outputPath string, password []byte) error {
	var input io.Reader
	var output io.Writer

	if inputPath == "-" {
		input = os.Stdin
	} else {
		file, err := os.Open(inputPath)
		if err != nil {
			return err
		}
		defer file.Close()
		input = file
	}

	if outputPath == "-" {
		output = os.Stdout
	} else {
		file, err := os.Create(outputPath)
		if err != nil {
			return err
		}
		defer file.Close()
		output = file
	}

	plaintext, err := io.ReadAll(input)
	if err != nil {
		return err
	}

	ciphertext, err := Encrypt(plaintext, password)
	if err != nil {
		return err
	}

	_, err = output.Write(ciphertext)
	return err
}

func DecryptFile(inputPath, outputPath string, password []byte) error {
	var input io.Reader
	var output io.Writer

	if inputPath == "-" {
		input = os.Stdin
	} else {
		file, err := os.Open(inputPath)
		if err != nil {
			return err
		}
		defer file.Close()
		input = file
	}

	if outputPath == "-" {
		output = os.Stdout
	} else {
		file, err := os.Create(outputPath)
		if err != nil {
			return err
		}
		defer file.Close()
		output = file
	}

	ciphertext, err := io.ReadAll(input)
	if err != nil {
		return err
	}

	plaintext, err := Decrypt(ciphertext, password)
	if err != nil {
		return err
	}

	_, err = output.Write(plaintext)
	return err
}
