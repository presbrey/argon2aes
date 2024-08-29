package base92

import (
	"bytes"
	"testing"
)

func TestBase92(t *testing.T) {
	testCases := []struct {
		name     string
		input    []byte
		expected string
	}{
		{"Empty", []byte{}, ""},
		{"Single byte", []byte{0}, "0"},
		{"Hello World", []byte("Hello World"), "2S4n*AHcqRHp?g"},
		{"Binary data", []byte{0xFF, 0x00, 0xAA, 0x55}, "X=eA5"},
		{"Long text", []byte("The quick brown fox jumps over the lazy dog"), "92z[FYX$iQ/LRQ2'8uH;D5L4)#f2PoEy!MX2qxr3ue9qK?t4qiP_n"},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			encoded := DefaultEncoding.EncodeToString(tc.input)
			if encoded != tc.expected {
				t.Errorf("EncodeToString(%v) = %+v, want %+v", tc.input, encoded, tc.expected)
			}

			decoded, err := DefaultEncoding.DecodeString(tc.expected)
			if err != nil {
				t.Errorf("DecodeString(%s) returned error: %v", tc.expected, err)
			}
			if !bytes.Equal(decoded, tc.input) {
				t.Errorf("DecodeString(%s) = %v, want %v", tc.expected, decoded, tc.input)
			}
		})
	}
}

func TestInvalidInput(t *testing.T) {
	invalidInputs := []string{
		"invalid char £",
		"another invalid ñ",
	}

	for _, input := range invalidInputs {
		t.Run(input, func(t *testing.T) {
			_, err := DefaultEncoding.DecodeString(input)
			if err == nil {
				t.Errorf("DecodeString(%s) should return an error", input)
			}
		})
	}
}

func TestRoundTrip(t *testing.T) {
	testData := [][]byte{
		{},
		{0},
		{255},
		bytes.Repeat([]byte{0}, 1000),
		bytes.Repeat([]byte{255}, 1000),
	}

	for i, data := range testData {
		encoded := DefaultEncoding.EncodeToString(data)
		decoded, err := DefaultEncoding.DecodeString(encoded)
		if err != nil {
			t.Errorf("Test case %d: DecodeString returned error: %v", i, err)
		}
		if !bytes.Equal(data, decoded) {
			t.Errorf("Test case %d: Round trip failed. Original: %v, Got: %v", i, data, decoded)
		}
	}
}
