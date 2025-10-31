package des

import (
	"fmt"

	permute "crypto-lab/internal/ciphers/permute"
)

type DESRoundFunction struct{}

func NewDESRoundFunction() *DESRoundFunction {
	return &DESRoundFunction{}
}

func (d *DESRoundFunction) Transform(inputBlock, roundKey []byte) ([]byte, error) {

	expanded, err := permute.Permute(inputBlock, DES.E(), true, true)
	if err != nil {
		return nil, err
	}

	if len(expanded) != len(roundKey) {
		return nil, fmt.Errorf("expanded block size %d doesn't match round key size %d", len(expanded), len(roundKey))
	}

	xored := make([]byte, len(expanded))
	for i := range expanded {
		xored[i] = expanded[i] ^ roundKey[i]
	}

	sboxResult := d.applySBoxes(xored)

	result, err := permute.Permute(sboxResult, DES.P(), true, true)
	if err != nil {
		return nil, err
	}

	return result, nil
}

func (d *DESRoundFunction) applySBoxes(input []byte) []byte {
	if len(input) != 6 {
		panic("S-box input must be 6 bytes")
	}

	var bits48 uint64
	for i := 0; i < 6; i++ {
		bits48 = (bits48 << 8) | uint64(input[i])
	}

	var output uint32

	for i := 0; i < 8; i++ {

		shift := 42 - i*6
		bits6 := (bits48 >> uint(shift)) & 0x3F

		row := ((bits6 & 0x20) >> 4) | (bits6 & 0x01)
		column := (bits6 >> 1) & 0x0F

		sboxValue := DES.S()[i][row][column]

		output = (output << 4) | uint32(sboxValue)
	}

	result := make([]byte, 4)
	result[0] = byte((output >> 24) & 0xFF)
	result[1] = byte((output >> 16) & 0xFF)
	result[2] = byte((output >> 8) & 0xFF)
	result[3] = byte(output & 0xFF)

	return result
}

func (d *DESRoundFunction) GetInputBlockSize() int  { return 4 }
func (d *DESRoundFunction) GetRoundKeySize() int    { return 6 }
func (d *DESRoundFunction) GetOutputBlockSize() int { return 4 }
