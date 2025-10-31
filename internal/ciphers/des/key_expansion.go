package des

import (
	permute "crypto-lab/internal/ciphers/permute"
	//"encoding/binary"
	"fmt"
)

type DESKeyExpansion struct{}

func NewDESKeyExpansion() *DESKeyExpansion {
	return &DESKeyExpansion{}
}
func (d *DESKeyExpansion) GenerateRoundKeys(key []byte) ([][]byte, error) {
	if len(key) != 8 {
		return nil, fmt.Errorf("DES key must be 8 bytes (64 bits), got %d", len(key))
	}

	// PC-1
	cd7bytes, err := permute.Permute(key, DES.PC1(), true, true)
	if err != nil {
		return nil, fmt.Errorf("PC-1 permutation failed: %w", err)
	}

	if len(cd7bytes) != 7 {
		return nil, fmt.Errorf("PC-1 should return 7 bytes, got %d", len(cd7bytes))
	}

	// 56 в C  и D по 28
	C, D := SplitCD(cd7bytes)

	roundKeys := make([][]byte, 16)

	for i := 0; i < 16; i++ {
		shift := DES.SHIFT_SCHEDULE()[i]

		C = RotateLeft(C, shift)
		D = RotateLeft(D, shift)

		// обратно в 56
		cd56bytes := MergeCD(C, D)

		// PC-2
		roundKeys[i], err = permute.Permute(cd56bytes, DES.PC2(), true, true)
		if err != nil {
			return nil, fmt.Errorf("PC2 permutation round %d failed: %w", i, err)
		}
	}

	return roundKeys, nil
}

func SplitCD(cd7 []byte) (C, D uint32) {

	var cd56 uint64
	for i := 0; i < 7; i++ {
		cd56 = (cd56 << 8) | uint64(cd7[i])
	}

	C = uint32((cd56 >> 28) & 0x0FFFFFFF)
	D = uint32(cd56 & 0x0FFFFFFF)

	return
}

func MergeCD(C, D uint32) []byte {

	cd56 := (uint64(C&0x0FFFFFFF) << 28) | uint64(D&0x0FFFFFFF)

	result := make([]byte, 7)
	for i := 6; i >= 0; i-- {
		result[i] = byte(cd56 & 0xFF)
		cd56 >>= 8
	}
	return result
}

// циклический сдвиг влево на n бит

func RotateLeft(value uint32, n int) uint32 {

	const mask28 = 0x0FFFFFFF
	n = n % 28

	return ((value << n) | (value >> (28 - n))) & mask28
}
