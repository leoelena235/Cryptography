package modes

import (
	"bytes"
	"crypto-lab/internal/ciphers"
	"crypto-lab/internal/modes"
	"testing"
)

type mockCipher struct{}

func (m *mockCipher) Encrypt(block []byte) ([]byte, error) {
	result := make([]byte, len(block))
	copy(result, block)
	return result, nil
}

func (m *mockCipher) Decrypt(block []byte) ([]byte, error) {
	result := make([]byte, len(block))
	copy(result, block)
	return result, nil
}

func (m *mockCipher) GetBlockSize() int                { return 8 }
func (m *mockCipher) SetSymmetricKey(key []byte) error { return nil }

// Тест PKCS7 при разных размерах
func TestPKCS7Padding(t *testing.T) {
	cipher := &mockCipher{}

	testCases := []struct {
		name string
		data []byte
	}{
		{"1 байт", []byte("X")},
		{"7 байт", []byte("1234567")},
		{"8 байт ", []byte("12345678")},
		{"9 байт", []byte("123456789")},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			iv, _ := modes.GenerateRandomBytes(8)
			ctx, err := modes.NewSymmetricContext(cipher, ciphers.CBC, ciphers.PKCS7, iv)
			if err != nil {
				t.Fatal(err)
			}

			encrypted, err := ctx.Encrypt(tc.data)
			if err != nil {
				t.Fatalf("Error encrypt: %v", err)
			}

			decrypted, err := ctx.Decrypt(encrypted)
			if err != nil {
				t.Fatalf("error decrypt: %v", err)
			}

			if !bytes.Equal(tc.data, decrypted) {
				t.Errorf("mismatch:\n  expected: %v\n  got: %v", tc.data, decrypted)
			}
		})
	}
}
