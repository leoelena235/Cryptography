package permute

import (
	"bytes"
	"testing"
)

func TestPermuteSwapBytes(t *testing.T) {
	data := []byte{0xFF, 0x00}
	pBlock := []int{9, 10, 11, 12, 13, 14, 15, 16, 1, 2, 3, 4, 5, 6, 7, 8}

	result, err := Permute(data, pBlock, false, true)
	if err != nil {
		t.Fatalf("Error: %v", err)
	}

	expected := []byte{0x00, 0xFF}
	if !bytes.Equal(result, expected) {
		t.Errorf("Expected %v, got %v", expected, result)
	}
}

// 0b10101010 (170), 0b11001100 (204)
// 0b10100000 (160)
func TestPermuteEvenBits(t *testing.T) {
	data := []byte{0b10101010, 0b11001100}
	pBlock := []int{0, 2, 4, 6, 8, 10, 12, 14}

	result, err := Permute(data, pBlock, false, false)
	if err != nil {
		t.Fatalf("Error: %v", err)
	}

	expected := []byte{0b10100000} // 160 = 0xA0
	if !bytes.Equal(result, expected) {
		t.Errorf("Expected %v (0x%02x), got %v (0x%02x)",
			expected, expected, result, result)
	}
}

func TestPermuteErrors(t *testing.T) {
	tests := []struct {
		name    string
		data    []byte
		pBlock  []int
		wantErr bool
	}{
		{"empty input", []byte{}, []int{0, 1}, true},
		{"empty pBlock", []byte{0xFF}, []int{}, true},
		{"index out of range", []byte{0xFF}, []int{100}, true},
		{"valid data", []byte{0xFF}, []int{0, 1, 2, 3, 4, 5, 6, 7}, false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, err := Permute(tt.data, tt.pBlock, false, false)
			if (err != nil) != tt.wantErr {
				if tt.wantErr {
					t.Errorf("Expected error, but got none")
				} else {
					t.Errorf("Unexpected error: %v", err)
				}
			}
		})
	}
}

func TestPermuteReverseBits(t *testing.T) {
	data := []byte{0b10101010}
	pBlock := []int{8, 7, 6, 5, 4, 3, 2, 1}

	result, err := Permute(data, pBlock, false, true)
	if err != nil {
		t.Fatalf("Error: %v", err)
	}

	expected := []byte{0b01010101}
	if !bytes.Equal(result, expected) {
		t.Errorf("Expected %v (0b01010101), got %v (0b%08b)",
			expected, result, result)
	}
}

func TestPermuteAllZeros(t *testing.T) {
	data := []byte{0x00, 0x00}
	pBlock := []int{1, 2, 3, 4, 5, 6, 7, 8}

	result, err := Permute(data, pBlock, false, true)
	if err != nil {
		t.Fatalf("Error: %v", err)
	}

	expected := []byte{0x00}
	if !bytes.Equal(result, expected) {
		t.Errorf("Expected %v, got %v", expected, result)
	}
}
