[![Go Report Card](https://goreportcard.com/badge/github.com/presbrey/argon2aes)](https://goreportcard.com/report/github.com/presbrey/argon2aes)
[![codecov](https://codecov.io/gh/presbrey/argon2aes/branch/main/graph/badge.svg)](https://codecov.io/gh/presbrey/argon2aes)
![Go Test](https://github.com/presbrey/argon2aes/workflows/Go%20Test/badge.svg)
[![GoDoc](https://godoc.org/github.com/presbrey/argon2aes?status.svg)](https://godoc.org/github.com/presbrey/argon2aes)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)

# A2A: Argon2 and AES-256 Encryption Tool

A2A is a secure encryption tool that uses Argon2 for key derivation and AES-256 for encryption. It provides both a Command Line Interface (CLI) and an API for easy integration into your projects.

## Installation

### Pre-built Binaries

You can download pre-built binaries for various platforms from the [latest release page](https://github.com/presbrey/argon2aes/releases/latest). Choose the appropriate version for your operating system and architecture.

After downloading, make the binary executable and move it to a directory in your system's PATH. For example, on Unix-like systems:

```
chmod +x a2a-<os>-<arch>
sudo mv a2a-<os>-<arch> /usr/local/bin/a2a
```

Replace `<os>` and `<arch>` with your operating system and architecture.

### Building from Source

If you prefer to build from source or need a version for a platform without pre-built binaries, you can use the Go tool. Make sure you have Go installed on your system, then run:

```
go install github.com/presbrey/argon2aes/cmd/a2a@latest
```

This will download, compile, and install the `a2a` command in your `$GOPATH/bin` directory. Make sure this directory is in your system's PATH to run the `a2a` command from anywhere.

## CLI Usage

The CLI allows you to encrypt and decrypt files directly from the command line. It supports both short and long forms for flags.

To encrypt a file:
```
a2a -e -i <input_file> -o <output_file>
a2a --encrypt --in <input_file> --out <output_file>
```

To decrypt a file:
```
a2a -d -i <input_file> -o <output_file>
a2a --decrypt --in <input_file> --out <output_file>
```

Additional flags:
- `-p, --passphrase`: Specify the passphrase (not recommended for security reasons)
- `-k, --key`: Specify a base64-encoded encryption key
- `-i, --in`: Input file (default: stdin)
- `-o, --out`: Output file (default: stdout)
- `-6, --base64`: Use standard base64 encoding for input/output
- `-9, --base92`: Use base92 encoding for input/output
- `-u, --url64`: Use URL-safe base64 encoding for input/output

You will be prompted to enter a passphrase if not provided via the command line.

## Encoding Options

A2A supports different encoding options for input and output:

1. **Base64**: Use `-6` or `--base64` flag for standard base64 encoding.
2. **Base92**: Use `-9` or `--base92` flag for base92 encoding.
3. **URL-safe Base64**: Use `-u` or `--url64` flag for URL-safe base64 encoding.

These encoding options can be useful when working with different types of data or when you need to ensure compatibility with specific systems or protocols.

Example usage with encoding:
```
a2a -e -i <input_file> -o <output_file> -6
a2a -d -i <input_file> -o <output_file> -u
```

Note: You can only use one encoding option at a time.

## API Usage

The A2A package provides Go functions for encryption and decryption that you can use in your own projects.

```go
import "path/to/a2a"

// Encrypt a file
err := a2a.EncryptFile("input.txt", "encrypted.bin", []byte("password"))

// Decrypt a file
err := a2a.DecryptFile("encrypted.bin", "decrypted.txt", []byte("password"))
```

## Security Features

### Argon2 Key Derivation

A2A uses Argon2, the winner of the Password Hashing Competition, for key derivation. Argon2 provides:

- Memory-hard algorithm, resistant to GPU cracking attempts
- Configurable memory and CPU cost parameters
- Salt for protection against rainbow table attacks

### AES-256 Encryption

For the actual encryption, A2A employs AES (Advanced Encryption Standard) with a 256-bit key. AES-256 offers:

- Robust security, approved for top secret information by the NSA
- Fast performance on a wide range of hardware
- Wide adoption and extensive security analysis

By combining Argon2 for key derivation and AES-256 for encryption, A2A provides a high level of security for your sensitive data.

## License

This project is licensed under the MIT License. See the [LICENSE](LICENSE) file for details.
