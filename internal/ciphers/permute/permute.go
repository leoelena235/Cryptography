package permute

import "fmt"

func Permute(input []byte, pBlock []int, msbFirst bool, oneIndexed bool) ([]byte, error) {
	if len(input) == 0 {
		return nil, fmt.Errorf("input is empty")
	}
	if len(pBlock) == 0 {
		return nil, fmt.Errorf("pBlock is empty")
	}

	totalBits := len(input) * 8
	outputSizeBytes := (len(pBlock) + 7) / 8
	output := make([]byte, outputSizeBytes)

	for outBit := 0; outBit < len(pBlock); outBit++ {
		inBit := pBlock[outBit]

		if oneIndexed {
			inBit--
		}

		if inBit < 0 || inBit >= totalBits {
			return nil, fmt.Errorf("illegal bit position: %d out of range [0, %d]", inBit, totalBits-1)
		}

		bit := extractBit(input, inBit, msbFirst)

		setBit(&output, outBit, bit, msbFirst)
	}

	return output, nil
}

func extractBit(data []byte, bitPos int, msbFirst bool) byte {
	byteIdx := bitPos / 8
	bitOffset := bitPos % 8

	var physicalPos int
	if msbFirst {
		physicalPos = 7 - bitOffset
	} else {
		physicalPos = bitOffset
	}

	return (data[byteIdx] >> uint(physicalPos)) & 1
}

func setBit(data *[]byte, bitPos int, bit byte, msbFirst bool) {
	byteIdx := bitPos / 8
	bitOffset := bitPos % 8

	var physicalPos int
	if msbFirst {
		physicalPos = 7 - bitOffset
	} else {
		physicalPos = bitOffset
	}

	if bit == 1 {
		(*data)[byteIdx] |= (1 << uint(physicalPos))
	}
}

func InversePBlock(pBlock []int, oneIndexed bool) ([]int, error) {
	m := len(pBlock)
	if m == 0 {
		return nil, fmt.Errorf("pBlock is empty")
	}

	inv := make([]int, m)
	for i := range inv {
		inv[i] = -1
	}

	for i, pos := range pBlock {
		if oneIndexed {
			pos--
		}

		if pos < 0 || pos >= m {
			return nil, fmt.Errorf("pBlock element out of range: %d", pos)
		}

		if inv[pos] != -1 {
			return nil, fmt.Errorf("pBlock is not a valid permutation")
		}

		inv[pos] = i
		if oneIndexed {
			inv[pos]++
		}
	}

	for i := 0; i < m; i++ {
		if inv[i] == -1 {
			return nil, fmt.Errorf("pBlock is not a full permutation ")
		}
	}

	return inv, nil
}
