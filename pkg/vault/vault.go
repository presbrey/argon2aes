package vault

import (
	"encoding/json"
	"fmt"
	"io/fs"
	"os"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/presbrey/argon2aes"
	"github.com/presbrey/argon2aes/pkg/base92"
)

// Vault holds encrypted environment data of various types and provides thread-safe access
type Vault struct {
	data sync.Map
}

// Load12F attempts to load a vault using 12-factor app environment variables
// It looks for an environment variable at envKey to get the cipher key
// and uses the provided filesystem and path to load the vault
func Load12F(fsys fs.FS, path, envKey string) (*Vault, error) {
	cipherKey := os.Getenv(envKey)
	if cipherKey == "" {
		return nil, fmt.Errorf("environment variable %s not set or empty", envKey)
	}

	return LoadB92(fsys, path, cipherKey)
}

// LoadB92 reads and decrypts a base92-encoded environment file, returning a new Vault
func LoadB92(fsys fs.FS, path, key string) (*Vault, error) {
	vault := &Vault{}

	d, err := fs.ReadFile(fsys, path)
	if err != nil {
		return nil, err
	}

	d = []byte(strings.ReplaceAll(string(d), "\n", ""))
	d, err = base92.DefaultEncoding.DecodeString(string(d))
	if err != nil {
		return nil, err
	}

	d, err = argon2aes.Decrypt(d, []byte(key))
	if err != nil {
		return nil, err
	}

	// First unmarshal into a map that can hold any JSON type
	tempMap := make(map[string]any)
	err = json.Unmarshal(d, &tempMap)
	if err != nil {
		return nil, err
	}

	// Then store each key-value pair in the sync.Map
	for k, v := range tempMap {
		vault.data.Store(k, v)
	}

	return vault, nil
}

// Get retrieves a specific key from the vault
func (v *Vault) Get(key string) any {
	value, ok := v.data.Load(key)
	if !ok {
		return nil
	}

	return value
}

// GetString retrieves a specific key from the vault as a string
func (v *Vault) GetString(key string) string {
	value, ok := v.data.Load(key)
	if !ok {
		return ""
	}

	// Convert value to string based on its type
	switch v := value.(type) {
	case string:
		return v
	case nil:
		return ""
	default:
		// For other types, convert to JSON string
		bytes, err := json.Marshal(v)
		if err != nil {
			return ""
		}
		return string(bytes)
	}
}

// GetBool retrieves a specific key from the vault as a boolean
func (v *Vault) GetBool(key string) bool {
	value, ok := v.data.Load(key)
	if !ok {
		return false
	}

	switch v := value.(type) {
	case bool:
		return v
	case string:
		b, err := strconv.ParseBool(v)
		if err != nil {
			return false
		}
		return b
	case float64:
		return v != 0
	case int:
		return v != 0
	default:
		return false
	}
}

// GetInt retrieves a specific key from the vault as an integer
func (v *Vault) GetInt(key string) int {
	value, ok := v.data.Load(key)
	if !ok {
		return 0
	}

	switch v := value.(type) {
	case int:
		return v
	case float64:
		return int(v)
	case string:
		i, err := strconv.Atoi(v)
		if err != nil {
			return 0
		}
		return i
	case bool:
		if v {
			return 1
		}
		return 0
	default:
		return 0
	}
}

// GetFloat retrieves a specific key from the vault as a float64
func (v *Vault) GetFloat64(key string) float64 {
	value, ok := v.data.Load(key)
	if !ok {
		return 0
	}

	switch v := value.(type) {
	case float64:
		return v
	case int:
		return float64(v)
	case string:
		f, err := strconv.ParseFloat(v, 64)
		if err != nil {
			return 0
		}
		return f
	case bool:
		if v {
			return 1
		}
		return 0
	default:
		return 0
	}
}

// GetTime retrieves a specific key from the vault as a time.Time
func (v *Vault) GetTime(key string) time.Time {
	value, ok := v.data.Load(key)
	if !ok {
		return time.Time{}
	}

	switch v := value.(type) {
	case string:
		// Try parsing common time formats
		for _, layout := range []string{
			time.RFC3339,
			time.RFC3339Nano,
			"2006-01-02T15:04:05",
			"2006-01-02",
			time.RFC822,
			time.RFC850,
			time.RFC1123,
		} {
			t, err := time.Parse(layout, v)
			if err == nil {
				return t
			}
		}
		return time.Time{}
	default:
		return time.Time{}
	}
}

// Keys returns a slice of all keys in the vault
func (v *Vault) Keys() []string {
	var keys []string

	v.data.Range(func(key, value interface{}) bool {
		keys = append(keys, key.(string))
		return true
	})

	return keys
}
