package modes

import (
	cryptorand "crypto/rand"
	"errors"
	"fmt"
)

func GenerateRandomBytes(size int) ([]byte, error) {
	if size <= 0 {
		return nil, errors.New("size must be positive")
	}
	bytes := make([]byte, size)
	_, err := cryptorand.Read(bytes)
	if err != nil {
		return nil, fmt.Errorf("failed to generate random bytes: %v", err)
	}
	return bytes, nil
}

func (ctx *SymmetricContext) getNonce() []byte {
	if len(ctx.params) > 0 {
		if nonce, ok := ctx.params[0].([]byte); ok {
			return nonce
		}
	}

	nonceSize := ctx.blockSize / 2
	nonce, err := GenerateRandomBytes(nonceSize)
	if err != nil {
		nonce = make([]byte, nonceSize)
	}
	return nonce
}

func (ctx *SymmetricContext) getRandomDeltaSeed() int64 {
	if len(ctx.params) > 1 {
		if seed, ok := ctx.params[1].(int64); ok {
			return seed
		}
	}
	return 52 
}

func XOR(a, b []byte) ([]byte, error) {
	if len(a) != len(b) {
		return nil, errors.New("XOR: slices must have equal length")
	}
	result := make([]byte, len(a))
	for i := range a {
		result[i] = a[i] ^ b[i]
	}
	return result, nil
}
