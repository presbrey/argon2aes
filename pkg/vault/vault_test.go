package vault

import (
	"encoding/json"
	"io/fs"
	"os"
	"reflect"
	"strings"
	"testing"
	"testing/fstest"
	"time"

	"github.com/presbrey/argon2aes"
	"github.com/presbrey/pkg/base92"
)

// mockFS is a helper function to create a mock filesystem for testing
func mockFS(t *testing.T, path string, data map[string]any, key string) fs.FS {
	t.Helper()

	// Marshal data to JSON
	jsonData, err := json.Marshal(data)
	if err != nil {
		t.Fatalf("Failed to marshal test data: %v", err)
	}

	// Encrypt the data
	encrypted, err := argon2aes.Encrypt(jsonData, []byte(key))
	if err != nil {
		t.Fatalf("Failed to encrypt test data: %v", err)
	}

	// Encode to base92
	encoded := base92.Encode(encrypted)

	// Create a mock filesystem
	return fstest.MapFS{
		path: &fstest.MapFile{
			Data: []byte(encoded),
			Mode: 0644,
		},
	}
}

func TestLoadB92(t *testing.T) {
	testCases := []struct {
		name    string
		data    map[string]any
		key     string
		path    string
		wantErr bool
	}{
		{
			name: "Basic",
			data: map[string]any{
				"string_key": "value",
				"int_key":    42,
				"bool_key":   true,
				"float_key":  3.14,
			},
			key:     "testkey",
			path:    "test.env",
			wantErr: false,
		},
		{
			name:    "Empty",
			data:    map[string]any{},
			key:     "testkey",
			path:    "empty.env",
			wantErr: false,
		},
		{
			name: "Complex",
			data: map[string]any{
				"nested": map[string]any{
					"key": "value",
				},
				"array": []any{1, 2, 3},
			},
			key:     "testkey",
			path:    "complex.env",
			wantErr: false,
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			fsys := mockFS(t, tc.path, tc.data, tc.key)

			v, err := LoadB92(fsys, tc.path, tc.key)
			if (err != nil) != tc.wantErr {
				t.Fatalf("LoadB92() error = %v, wantErr %v", err, tc.wantErr)
			}

			if tc.wantErr {
				return
			}

			// Verify all keys and values are present
			for k, expected := range tc.data {
				// For maps and arrays, we need to compare the JSON representation
				if reflect.TypeOf(expected).Kind() == reflect.Map || reflect.TypeOf(expected).Kind() == reflect.Slice {
					expectedJSON, _ := json.Marshal(expected)
					actual := v.GetString(k)
					if actual != string(expectedJSON) {
						t.Errorf("GetString(%q) = %v, want %v", k, actual, string(expectedJSON))
					}
				} else {
					switch e := expected.(type) {
					case string:
						if got := v.GetString(k); got != e {
							t.Errorf("GetString(%q) = %v, want %v", k, got, e)
						}
					case int:
						if got := v.GetInt(k); got != e {
							t.Errorf("GetInt(%q) = %v, want %v", k, got, e)
						}
					case float64:
						if got := v.GetFloat64(k); got != e {
							t.Errorf("GetFloat64(%q) = %v, want %v", k, got, e)
						}
					case bool:
						if got := v.GetBool(k); got != e {
							t.Errorf("GetBool(%q) = %v, want %v", k, got, e)
						}
					}
				}
			}
		})
	}
}

func TestLoadB92_Errors(t *testing.T) {
	testCases := []struct {
		name        string
		setupFS     func() fs.FS
		path        string
		key         string
		expectedErr string
	}{
		{
			name: "FileNotFound",
			setupFS: func() fs.FS {
				return fstest.MapFS{}
			},
			path:        "nonexistent.env",
			key:         "testkey",
			expectedErr: "file does not exist",
		},
		{
			name: "InvalidBase92",
			setupFS: func() fs.FS {
				return fstest.MapFS{
					"invalid.env": &fstest.MapFile{
						Data: []byte("not base92 encoded~"), // '~' is not in the base92 charset
						Mode: 0644,
					},
				}
			},
			path:        "invalid.env",
			key:         "testkey",
			expectedErr: "base92: invalid character", 
		},
		{
			name: "WrongKey",
			setupFS: func() fs.FS {
				// Create valid encrypted data with one key
				data := map[string]any{"test": "value"}
				jsonData, _ := json.Marshal(data)
				encrypted, _ := argon2aes.Encrypt(jsonData, []byte("correctkey"))
				encoded := base92.Encode(encrypted)

				return fstest.MapFS{
					"test.env": &fstest.MapFile{
						Data: []byte(encoded),
						Mode: 0644,
					},
				}
			},
			path:        "test.env",
			key:         "wrongkey", // Using wrong key to decrypt
			expectedErr: "authentication failed",
		},
		{
			name: "InvalidJSON",
			setupFS: func() fs.FS {
				// Create invalid JSON data
				invalidJSON := []byte("{not valid json")
				encrypted, _ := argon2aes.Encrypt(invalidJSON, []byte("testkey"))
				encoded := base92.Encode(encrypted)

				return fstest.MapFS{
					"invalid_json.env": &fstest.MapFile{
						Data: []byte(encoded),
						Mode: 0644,
					},
				}
			},
			path:        "invalid_json.env",
			key:         "testkey",
			expectedErr: "invalid character",
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			fsys := tc.setupFS()

			_, err := LoadB92(fsys, tc.path, tc.key)
			if err == nil {
				t.Fatalf("LoadB92() expected error, got nil")
			}

			if !strings.Contains(err.Error(), tc.expectedErr) {
				t.Errorf("LoadB92() error = %v, expected to contain %v", err, tc.expectedErr)
			}
		})
	}
}

func TestLoad12F(t *testing.T) {
	// Setup test environment
	testData := map[string]any{
		"key1": "value1",
		"key2": 42,
	}
	testPath := "test.env"
	testKey := "secret_key"
	testName := "TEST_APP"
	envVarName := "TEST_APP"

	// Save original environment
	origEnv := os.Getenv(envVarName)
	defer os.Setenv(envVarName, origEnv)

	// Set environment for test
	os.Setenv(envVarName, testKey)

	// Create mock filesystem
	fsys := mockFS(t, testPath, testData, testKey)

	// Test successful load
	v, err := Load12F(fsys, testPath, testName)
	if err != nil {
		t.Fatalf("Load12F() error = %v", err)
	}

	// Verify data
	if v.GetString("key1") != "value1" {
		t.Errorf("GetString(key1) = %v, want %v", v.GetString("key1"), "value1")
	}
	if v.GetInt("key2") != 42 {
		t.Errorf("GetInt(key2) = %v, want %v", v.GetInt("key2"), 42)
	}

	// Test with missing environment variable
	os.Unsetenv(envVarName)
	_, err = Load12F(fsys, testPath, testName)
	if err == nil {
		t.Error("Load12F() with missing env var expected error, got nil")
	}
}

func TestGetString(t *testing.T) {
	v := &Vault{}
	v.data.Store("string", "value")
	v.data.Store("int", 42)
	v.data.Store("float", 3.14)
	v.data.Store("bool", true)
	v.data.Store("nil", nil)
	v.data.Store("map", map[string]any{"key": "value"})
	v.data.Store("array", []any{1, 2, 3})

	testCases := []struct {
		name     string
		key      string
		expected string
	}{
		{"String", "string", "value"},
		{"Int", "int", "42"},
		{"Float", "float", "3.14"},
		{"Bool", "bool", "true"},
		{"Nil", "nil", ""},
		{"Map", "map", `{"key":"value"}`},
		{"Array", "array", `[1,2,3]`},
		{"NonExistent", "nonexistent", ""},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			result := v.GetString(tc.key)
			if result != tc.expected {
				t.Errorf("GetString(%q) = %v, want %v", tc.key, result, tc.expected)
			}
		})
	}
}

func TestGetBool(t *testing.T) {
	v := &Vault{}
	v.data.Store("true", true)
	v.data.Store("false", false)
	v.data.Store("string_true", "true")
	v.data.Store("string_false", "false")
	v.data.Store("string_invalid", "not a bool")
	v.data.Store("int_1", 1)
	v.data.Store("int_0", 0)
	v.data.Store("float_1", 1.0)
	v.data.Store("float_0", 0.0)
	v.data.Store("map", map[string]any{})

	testCases := []struct {
		name     string
		key      string
		expected bool
	}{
		{"True", "true", true},
		{"False", "false", false},
		{"StringTrue", "string_true", true},
		{"StringFalse", "string_false", false},
		{"StringInvalid", "string_invalid", false},
		{"Int1", "int_1", true},
		{"Int0", "int_0", false},
		{"Float1", "float_1", true},
		{"Float0", "float_0", false},
		{"Map", "map", false},
		{"NonExistent", "nonexistent", false},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			result := v.GetBool(tc.key)
			if result != tc.expected {
				t.Errorf("GetBool(%q) = %v, want %v", tc.key, result, tc.expected)
			}
		})
	}
}

func TestGetInt(t *testing.T) {
	v := &Vault{}
	v.data.Store("int", 42)
	v.data.Store("float", 3.14)
	v.data.Store("string_int", "42")
	v.data.Store("string_invalid", "not an int")
	v.data.Store("true", true)
	v.data.Store("false", false)
	v.data.Store("map", map[string]any{})

	testCases := []struct {
		name     string
		key      string
		expected int
	}{
		{"Int", "int", 42},
		{"Float", "float", 3},
		{"StringInt", "string_int", 42},
		{"StringInvalid", "string_invalid", 0},
		{"True", "true", 1},
		{"False", "false", 0},
		{"Map", "map", 0},
		{"NonExistent", "nonexistent", 0},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			result := v.GetInt(tc.key)
			if result != tc.expected {
				t.Errorf("GetInt(%q) = %v, want %v", tc.key, result, tc.expected)
			}
		})
	}
}

func TestGetFloat64(t *testing.T) {
	v := &Vault{}
	v.data.Store("float", 3.14)
	v.data.Store("int", 42)
	v.data.Store("string_float", "3.14")
	v.data.Store("string_invalid", "not a float")
	v.data.Store("true", true)
	v.data.Store("false", false)
	v.data.Store("map", map[string]any{})

	testCases := []struct {
		name     string
		key      string
		expected float64
	}{
		{"Float", "float", 3.14},
		{"Int", "int", 42.0},
		{"StringFloat", "string_float", 3.14},
		{"StringInvalid", "string_invalid", 0.0},
		{"True", "true", 1.0},
		{"False", "false", 0.0},
		{"Map", "map", 0.0},
		{"NonExistent", "nonexistent", 0.0},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			result := v.GetFloat64(tc.key)
			if result != tc.expected {
				t.Errorf("GetFloat64(%q) = %v, want %v", tc.key, result, tc.expected)
			}
		})
	}
}

func TestGetTime(t *testing.T) {
	v := &Vault{}

	// RFC3339 format
	rfc3339Time := "2023-01-02T15:04:05Z"
	expectedRFC3339, _ := time.Parse(time.RFC3339, rfc3339Time)
	v.data.Store("rfc3339", rfc3339Time)

	// Date only format
	dateOnly := "2023-01-02"
	expectedDateOnly, _ := time.Parse("2006-01-02", dateOnly)
	v.data.Store("date_only", dateOnly)

	// Invalid format
	v.data.Store("invalid_time", "not a time")

	// Non-string type
	v.data.Store("int", 42)

	testCases := []struct {
		name     string
		key      string
		expected time.Time
		isZero   bool
	}{
		{"RFC3339", "rfc3339", expectedRFC3339, false},
		{"DateOnly", "date_only", expectedDateOnly, false},
		{"InvalidTime", "invalid_time", time.Time{}, true},
		{"Int", "int", time.Time{}, true},
		{"NonExistent", "nonexistent", time.Time{}, true},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			result := v.GetTime(tc.key)
			if tc.isZero {
				if !result.IsZero() {
					t.Errorf("GetTime(%q) expected zero time, got %v", tc.key, result)
				}
			} else {
				if !result.Equal(tc.expected) {
					t.Errorf("GetTime(%q) = %v, want %v", tc.key, result, tc.expected)
				}
			}
		})
	}
}

func TestGet(t *testing.T) {
	v := &Vault{}
	testData := map[string]any{
		"string": "value",
		"int":    42,
		"bool":   true,
	}

	for k, val := range testData {
		v.data.Store(k, val)
	}

	result := v.Get("string")
	if result != "value" {
		t.Errorf("Get(%q) = %v, want %v", "string", result, "value")
	}

	result = v.Get("int")
	if result != 42 {
		t.Errorf("Get(%q) = %v, want %v", "int", result, 42)
	}

	result = v.Get("bool")
	if result != true {
		t.Errorf("Get(%q) = %v, want %v", "bool", result, true)
	}

	result = v.Get("nonexistent")
	if result != nil {
		t.Errorf("Get(%q) = %v, want nil", "nonexistent", result)
	}
}

func TestKeys(t *testing.T) {
	v := &Vault{}
	testKeys := []string{"key1", "key2", "key3"}

	for _, k := range testKeys {
		v.data.Store(k, "value")
	}

	keys := v.Keys()

	if len(keys) != len(testKeys) {
		t.Errorf("Keys() returned %d items, want %d", len(keys), len(testKeys))
	}

	// Check that all expected keys are present
	for _, expectedKey := range testKeys {
		found := false
		for _, actualKey := range keys {
			if actualKey == expectedKey {
				found = true
				break
			}
		}
		if !found {
			t.Errorf("Keys() missing expected key %q", expectedKey)
		}
	}
}
