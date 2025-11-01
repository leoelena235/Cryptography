package deal

import (
	"fmt"

	"crypto-lab/internal/ciphers"
	"crypto-lab/internal/ciphers/des"
)

type DEALKeyExpansion struct {
	keySize int
}

var fixedK0 = []byte{0x01, 0x23, 0x45, 0x67, 0x89, 0xAB, 0xCD, 0xEF}

func NewDEALKeyExpansion(keySize int) (ciphers.KeyExpansion, error) {
	if keySize != 16 && keySize != 24 && keySize != 32 {
		return nil, fmt.Errorf("invalid key size (%d)", keySize)
	}
	return &DEALKeyExpansion{keySize: keySize}, nil
}

func (d *DEALKeyExpansion) GenerateRoundKeys(Key []byte) ([][]byte, error) {
	if len(Key) != d.keySize {
		return nil, fmt.Errorf("key size mismatch (%d), got %d", d.keySize, len(Key))
	}

	numRounds := 6
	if d.keySize == 32 {
		numRounds = 8
	}

	numKeyBlocks := d.keySize / 8
	keyBlocks := make([][]byte, numKeyBlocks)

	for i := 0; i < numKeyBlocks; i++ {
		start := i * 8
		end := start + 8
		keyBlocks[i] = Key[start:end]
	}

	keyScheduleDES := des.NewDES()
	if err := keyScheduleDES.SetSymmetricKey(fixedK0); err != nil {
		return nil, fmt.Errorf("failed to set fixed K0: %w", err)
	}

	roundKeys := make([][]byte, numRounds)
	var prevRoundKey []byte = make([]byte, 8)

	for round := 0; round < numRounds; round++ {
		keyBlockIndex := round % numKeyBlocks

		input := make([]byte, 8)
		copy(input, keyBlocks[keyBlockIndex])

		for i := 0; i < 8; i++ {
			input[i] ^= prevRoundKey[i]
		}

		if round >= numKeyBlocks {
			roundConstant := generateRoundConstant(1 + round - numKeyBlocks)
			for i := 0; i < 8; i++ {
				input[i] ^= roundConstant[i]
			}
		}

		encrypted, err := keyScheduleDES.Encrypt(input)
		if err != nil {
			return nil, fmt.Errorf("DES encryption failed at round %d: %w", round, err)
		}

		roundKeys[round] = encrypted
		prevRoundKey = encrypted
	}

	return roundKeys, nil
}

func generateRoundConstant(bitPosition int) []byte {
	c := make([]byte, 8)
	byteIndex := bitPosition / 8
	bitIndex := bitPosition % 8
	if byteIndex < 8 {
		c[byteIndex] = 1 << bitIndex
	}
	return c
}

var _ ciphers.KeyExpansion = (*DEALKeyExpansion)(nil)
