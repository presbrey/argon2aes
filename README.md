# A2A: Argon2 and AES-256 Encryption Tool

A2A is a secure encryption tool that uses Argon2 for key derivation and AES-256 for encryption. It provides both a Command Line Interface (CLI) and an API for easy integration into your projects.

## CLI Usage

The CLI allows you to encrypt and decrypt files directly from the command line. It supports both short and long forms for flags.

To encrypt a file:
```
a2a -e -i <input_file> -o <output_file>
a2a --encrypt --input <input_file> --output <output_file>
```

To decrypt a file:
```
a2a -d -i <input_file> -o <output_file>
a2a --decrypt --input <input_file> --output <output_file>
```

Additional flags:
- `-p, --password`: Specify the password (not recommended for security reasons)
- `-v, --verbose`: Enable verbose output

You will be prompted to enter a password if not provided via the command line.

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
