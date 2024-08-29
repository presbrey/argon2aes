package base92

import (
	"bytes"
	"errors"
	"fmt"
	"math/big"
)

const alphabet = "0123456789abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ.-:+=^!/*?&<>()[]{}@%$#|;,_~`'"

var DefaultEncoding = NewEncoding(alphabet)

type Encoding struct {
	encode    [92]byte
	decodeMap [256]byte
}

func NewEncoding(encoder string) *Encoding {
	if len(encoder) != 92 {
		panic("encoding alphabet is not 92-bytes long: " + fmt.Sprint(len(encoder)))
	}

	e := new(Encoding)
	copy(e.encode[:], encoder)

	for i := 0; i < len(e.decodeMap); i++ {
		e.decodeMap[i] = 0xFF
	}
	for i := 0; i < len(encoder); i++ {
		e.decodeMap[encoder[i]] = byte(i)
	}
	return e
}

func (enc *Encoding) EncodeToString(src []byte) string {
	if len(src) == 0 {
		return ""
	}

	// Count leading zero bytes
	leadingZeros := 0
	for _, b := range src {
		if b == 0 {
			leadingZeros++
		} else {
			break
		}
	}

	x := new(big.Int).SetBytes(src)
	base := big.NewInt(92)
	zero := big.NewInt(0)
	mod := new(big.Int)

	var encoded []byte
	for x.Cmp(zero) > 0 {
		x.DivMod(x, base, mod)
		encoded = append(encoded, enc.encode[mod.Int64()])
	}

	// Add encoding for leading zeros
	for i := 0; i < leadingZeros; i++ {
		encoded = append(encoded, enc.encode[0])
	}

	// Reverse the encoded bytes
	for i, j := 0, len(encoded)-1; i < j; i, j = i+1, j-1 {
		encoded[i], encoded[j] = encoded[j], encoded[i]
	}

	return string(encoded)
}

func (enc *Encoding) DecodeString(s string) ([]byte, error) {
	if len(s) == 0 {
		return []byte{}, nil
	}

	x := new(big.Int)
	base := big.NewInt(92)
	leadingZeros := 0

	for _, c := range s {
		index := enc.decodeMap[c]
		if index == 0xFF {
			return nil, errors.New("invalid base92 character")
		}
		x.Mul(x, base)
		x.Add(x, big.NewInt(int64(index)))
		if index == 0 && x.Sign() == 0 {
			leadingZeros++
		}
	}

	decoded := x.Bytes()
	if len(decoded) == 0 && len(s) > 0 {
		// Handle the case of all zero bytes
		return bytes.Repeat([]byte{0}, leadingZeros), nil
	}

	// Prepend leading zeros if necessary
	if leadingZeros > 0 {
		zeros := bytes.Repeat([]byte{0}, leadingZeros)
		decoded = append(zeros, decoded...)
	}

	return decoded, nil
}
