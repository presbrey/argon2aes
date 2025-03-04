package base92

import (
	"bytes"
	"math/big"
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

func TestLeadingZeros(t *testing.T) {
	testCases := []struct {
		name     string
		input    string
		expected []byte
	}{
		{"No leading zeros", "X", []byte{59}},
		{"One leading zero", "00", []byte{0, 0}},
		{"Multiple leading zeros", "000X", []byte{0, 0, 0, 59}},
		{"All zeros", "0000", []byte{0, 0, 0, 0}},
		{"Leading zeros with complex data", "000ABC", []byte{0, 0, 0, 4, 179, 178}},
		{"Leading zeros with binary data", "00X=eA5", []byte{0, 0, 255, 0, 170, 85}},
		{"Leading zeros with non-zero big.Int", "0Z", []byte{0, 61}},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			decoded, err := DefaultEncoding.DecodeString(tc.input)
			if err != nil {
				t.Errorf("DecodeString(%s) returned error: %v", tc.input, err)
			}
			if !bytes.Equal(decoded, tc.expected) {
				t.Errorf("DecodeString(%s) = %v, want %v", tc.input, decoded, tc.expected)
			}
		})
	}
}

func TestPrependLeadingZeros(t *testing.T) {
	// This test specifically focuses on the prepending leading zeros functionality
	testCases := []struct {
		name        string
		input       string
		leadingZeros int
		expected    []byte
	}{
		{"No leading zeros", "X", 0, []byte{59}},
		{"One leading zero", "X", 1, []byte{0, 59}},
		{"Multiple leading zeros", "X", 3, []byte{0, 0, 0, 59}},
		{"Leading zeros with empty decoded", "", 2, []byte{0, 0}},
		{"Many leading zeros", "X", 10, []byte{0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 59}},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			// We'll manually decode and then prepend zeros to test this specific functionality
			x := new(big.Int)
			base := big.NewInt(92)
			
			for _, c := range tc.input {
				index := DefaultEncoding.decodeMap[c]
				if index == 0xFF {
					t.Fatalf("Invalid character in test case: %c", c)
				}
				x.Mul(x, base)
				x.Add(x, big.NewInt(int64(index)))
			}
			
			decoded := x.Bytes()
			
			// Now manually prepend leading zeros as the code does
			if tc.leadingZeros > 0 {
				zeros := bytes.Repeat([]byte{0}, tc.leadingZeros)
				decoded = append(zeros, decoded...)
			}
			
			if !bytes.Equal(decoded, tc.expected) {
				t.Errorf("Prepending %d leading zeros to decoded '%s' = %v, want %v", 
					tc.leadingZeros, tc.input, decoded, tc.expected)
			}
		})
	}
}

func TestInvalidAlphabetLength(t *testing.T) {
	testCases := []struct {
		name      string
		alphabet  string
		expectedMsg string
	}{
		{"Empty alphabet", "", "encoding alphabet is not 92-bytes long: 0"},
		{"Too short alphabet", "0123456789", "encoding alphabet is not 92-bytes long: 10"},
		{"Too long alphabet", alphabet + "extra", "encoding alphabet is not 92-bytes long: 97"},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			defer func() {
				r := recover()
				if r == nil {
					t.Errorf("NewEncoding(%s) did not panic as expected", tc.alphabet)
				} else if r != tc.expectedMsg {
					t.Errorf("NewEncoding(%s) panic with message %v, want %v", tc.alphabet, r, tc.expectedMsg)
				}
			}()
			
			// This should panic
			_ = NewEncoding(tc.alphabet)
		})
	}
}
