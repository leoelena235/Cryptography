package feistel

import (
	"bytes"
	//"crypto/rand"
	"encoding/hex"
	"testing"
)

type MockTransformation struct{}

func (m *MockTransformation) Transform(inputBlock, roundKey []byte) ([]byte, error) {
	result := make([]byte, len(inputBlock))
	for i := range inputBlock {
		result[i] = inputBlock[i] ^ roundKey[i%len(roundKey)]
	}
	return result, nil
}

func (m *MockTransformation) GetInputBlockSize() int  { return 4 }
func (m *MockTransformation) GetRoundKeySize() int    { return 4 }
func (m *MockTransformation) GetOutputBlockSize() int { return 4 }

type MockKeyExpansion struct{}

func (m *MockKeyExpansion) GenerateRoundKeys(key []byte) ([][]byte, error) {
	roundKeys := make([][]byte, 4)
	for i := 0; i < 4; i++ {
		roundKeys[i] = make([]byte, 4)
		for j := 0; j < 4; j++ {
			roundKeys[i][j] = key[j%len(key)] ^ byte(i)
		}
	}
	return roundKeys, nil
}

func TestFeistelClassicCases(t *testing.T) {
	roundFunc := &MockTransformation{}
	keyExp := &MockKeyExpansion{}
	feistel := NewFeistel(keyExp, roundFunc, 4)

	testCases := [][]byte{
		{0x01, 0x23, 0x45, 0x67, 0x89, 0xAB, 0xCD, 0xEF},
		{0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF}, //все 1
		{0x01, 0x23, 0x45, 0x67, 0x67, 0x45, 0x23, 0x01}, //симметрия
		{0x00, 0xFF, 0x00, 0xFF, 0xFF, 0x00, 0xFF, 0x00}, //чередование
		{0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00}, //все 0
		{0xC3, 0x9B, 0x17, 0x4E, 0xA5, 0x2C, 0xD1, 0xF8}, //радном
	}

	masterKey := []byte{0x12, 0x34, 0x56, 0x78}

	for idx, message := range testCases {
		ct, err := feistel.Encrypt(masterKey, message)
		if err != nil {
			t.Fatalf("encrypt error (test #%d): %v", idx+1, err)
		}

		pt, err := feistel.Decrypt(masterKey, ct)
		if err != nil {
			t.Fatalf("decrypt error (test #%d): %v", idx+1, err)
		}

		t.Logf("Test #%d  Input: %s Encrypted: %s Decrypted: %s",
			idx+1, hex.EncodeToString(message), hex.EncodeToString(ct), hex.EncodeToString(pt))

		if !bytes.Equal(pt, message) {
			t.Fatalf("round-trip fail (test #%d): want %s, got %s",
				idx+1, hex.EncodeToString(message), hex.EncodeToString(pt))
		}
	}
}

// тест неправильный ключ
func TestFeistelWrongKeyOrder(t *testing.T) {
	roundFunc := &MockTransformation{}
	keyExp := &MockKeyExpansion{}
	feistel := NewFeistel(keyExp, roundFunc, 4)

	msg := []byte{0xDE, 0xAD, 0xBE, 0xEF, 0xFE, 0xED, 0xFA, 0xCE}
	masterKey := []byte{0x12, 0x34, 0x56, 0x78}

	// шифруем с правильным ключом
	ct, err := feistel.Encrypt(masterKey, msg)
	if err != nil {
		t.Fatalf("encrypt failed: %v", err)
	}

	// дешифр с другим ключом
	wrongKey := []byte{0x87, 0x65, 0x43, 0x21}
	pt, err := feistel.Decrypt(wrongKey, ct)
	if err != nil {
		t.Fatalf("decrypt failed: %v", err)
	}

	// реузльтаты разные
	if bytes.Equal(pt, msg) {
		t.Fatal("decrypt with wrong key restored original message")
	}

	t.Logf(" Correct: wrong key did not restore original message")
	t.Logf("   Original:  %s", hex.EncodeToString(msg))
	t.Logf("   Decrypted: %s", hex.EncodeToString(pt))
}
