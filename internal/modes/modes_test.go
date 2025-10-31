package modes

import (
	"bytes"
	"crypto-lab/internal/ciphers"
	"testing"
)

type MockCipher struct{}

func (m *MockCipher) Encrypt(block []byte) ([]byte, error) {
	result := make([]byte, len(block))
	copy(result, block)
	return result, nil
}

func (m *MockCipher) Decrypt(block []byte) ([]byte, error) {
	result := make([]byte, len(block))
	copy(result, block)
	return result, nil
}

func (m *MockCipher) GetBlockSize() int                { return 8 }
func (m *MockCipher) SetSymmetricKey(key []byte) error { return nil }

func TestAllModes(t *testing.T) {
	cipher := &MockCipher{}
	testData := []byte("Hello, World!")

	modes := []ciphers.CipherMode{
		ciphers.ECB, ciphers.CBC, ciphers.PCBC,
		ciphers.CFB, ciphers.OFB, ciphers.CTR,
	}

	for _, mode := range modes {
		t.Run(mode.String(), func(t *testing.T) {
			var iv []byte
			var params []interface{}

			if mode == ciphers.CTR {
				nonce, _ := GenerateRandomBytes(4)
				params = append(params, nonce)
			} else {
				iv, _ = GenerateRandomBytes(8)
			}

			ctx, err := NewSymmetricContext(cipher, mode, ciphers.PKCS7, iv, params...)
			if err != nil {
				t.Fatalf("Failed to create context: %v", err)
			}

			encrypted, err := ctx.Encrypt(testData)
			if err != nil {
				t.Fatalf("Encryption error: %v", err)
			}

			decrypted, err := ctx.Decrypt(encrypted)
			if err != nil {
				t.Fatalf("Decryption error: %v", err)
			}

			if !bytes.Equal(testData, decrypted) {
				t.Errorf("Data mismatch: expected %v, got %v", testData, decrypted)
			}
		})
	}
}

func TestAllPaddings(t *testing.T) {
	cipher := &MockCipher{}
	testData := []byte("Short")

	paddings := []ciphers.PaddingMode{
		ciphers.Zeros, ciphers.ANSIX923,
		ciphers.PKCS7, ciphers.ISO10126,
	}

	for _, padding := range paddings {
		t.Run(padding.String(), func(t *testing.T) {
			iv, _ := GenerateRandomBytes(8)
			ctx, err := NewSymmetricContext(cipher, ciphers.CBC, padding, iv)
			if err != nil {
				t.Fatalf("Failed to create context: %v", err)
			}

			encrypted, err := ctx.Encrypt(testData)
			if err != nil {
				t.Fatalf("Encryption error: %v", err)
			}

			decrypted, err := ctx.Decrypt(encrypted)
			if err != nil {
				t.Fatalf("Decryption error: %v", err)
			}

			if !bytes.Equal(testData, decrypted) {
				t.Errorf("Data mismatch: expected %v, got %v", testData, decrypted)
			}
		})
	}
}