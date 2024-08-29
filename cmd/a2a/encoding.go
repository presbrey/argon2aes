package main

import (
	"errors"
	"math/big"
)

const base92Alphabet = "!#$%&'()*+,-./0123456789:;<=>?@ABCDEFGHIJKLMNOPQRSTUVWXYZ[\\]^_`abcdefghijklmnopqrstuvwxyz{|}~"

func base92encode(data []byte) string {
	if len(data) == 0 {
		return ""
	}

	x := new(big.Int).SetBytes(data)
	base := big.NewInt(92)
	zero := big.NewInt(0)
	mod := new(big.Int)

	var encoded []byte
	for x.Cmp(zero) > 0 {
		x.DivMod(x, base, mod)
		encoded = append(encoded, base92Alphabet[mod.Int64()])
	}

	// Reverse the encoded bytes
	for i, j := 0, len(encoded)-1; i < j; i, j = i+1, j-1 {
		encoded[i], encoded[j] = encoded[j], encoded[i]
	}

	return string(encoded)
}

func base92decode(s string) ([]byte, error) {
	if len(s) == 0 {
		return []byte{}, nil
	}

	x := new(big.Int)
	base := big.NewInt(92)
	for _, c := range s {
		index := int64(-1)
		for i, char := range base92Alphabet {
			if c == char {
				index = int64(i)
				break
			}
		}
		if index == -1 {
			return nil, errors.New("invalid base92 character")
		}
		x.Mul(x, base)
		x.Add(x, big.NewInt(index))
	}

	return x.Bytes(), nil
}
