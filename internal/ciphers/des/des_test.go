package des

import (
	"bytes"
	"encoding/hex"
	"testing"

	permute "crypto-lab/internal/ciphers/permute"
)

// Тест на генерацию раундовых ключей
func TestKeyExpansion(t *testing.T) {
	// Тестовый ключ
	key := []byte{0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01}

	keyExp := NewDESKeyExpansion()
	roundKeys, err := keyExp.GenerateRoundKeys(key)

	if err != nil {
		t.Fatalf("GenerateRoundKeys failed: %v", err)
	}

	// Чекаем что 16 ключей
	if len(roundKeys) != 16 {
		t.Errorf("Expected 16 round keys, got %d", len(roundKeys))
	}

	// каждый из них по 6байт
	for i, rk := range roundKeys {
		if len(rk) != 6 {
			t.Errorf("Round key %d has length %d, expected 6", i, len(rk))
		}
		t.Logf("Round key %2d: %s", i+1, hex.EncodeToString(rk))
	}
}

// Тест на IP^-1(IP(x))==x

func TestIPinverseProperty(t *testing.T) {
	tests := []struct {
		name      string
		plaintext string // hex
	}{
		{
			name:      "All zeros",
			plaintext: "0000000000000000",
		},
		{
			name:      "All ones",
			plaintext: "FFFFFFFFFFFFFFFF",
		},
		{
			name:      "Alternating AA",
			plaintext: "AAAAAAAAAAAAAAAA",
		},
		{
			name:      "Alternating 55",
			plaintext: "5555555555555555",
		},
		{
			name:      "Single MSB bit 1",
			plaintext: "8000000000000000",
		},
		{
			name:      "SSingle LSB bit 64",
			plaintext: "0000000000000001",
		},
		{
			name:      "Random pattern",
			plaintext: "0123456789ABCDEF",
		},
	}

	ipTable := DES.IP()
	ipInvTable := DES.IP_INV()

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Декодируем hex в байты
			input, err := hex.DecodeString(tt.plaintext)
			if err != nil {
				t.Fatalf("Failed to decode plaintext: %v", err)
			}

			if len(input) != 8 {
				t.Fatalf("Input must be 8 bytes, got %d", len(input))
			}

			// IP
			afterIP, err := permute.Permute(input, ipTable, true, true)
			if err != nil {
				t.Fatalf("IP permutation failed: %v", err)
			}

			//IP^-1
			recovered, err := permute.Permute(afterIP, ipInvTable, true, true)
			if err != nil {
				t.Fatalf("IP_INV permutation failed: %v", err)
			}

			// чекаем что вернулся исходный текст
			if !bytes.Equal(recovered, input) {
				t.Errorf("IP_INV(IP(x)) != x\n  Input:        %s\n  After IP:     %s\n  After IP_INV: %s",
					hex.EncodeToString(input),
					hex.EncodeToString(afterIP),
					hex.EncodeToString(recovered))
			}
		})
	}
}

// вектор из FIPS 46-3
func TestDESKnownVector(t *testing.T) {
	// Key:        133457799BBCDFF1
	// Plaintext:  0123456789ABCDEF
	// Ciphertext: 85E813540F0AB405

	key, _ := hex.DecodeString("133457799BBCDFF1")
	plaintext, _ := hex.DecodeString("0123456789ABCDEF")
	expectedCiphertext, _ := hex.DecodeString("85E813540F0AB405")

	t.Logf("Known DES Test Vector")
	t.Logf("Key:               %s", hex.EncodeToString(key))
	t.Logf("Plaintext:         %s", hex.EncodeToString(plaintext))
	t.Logf("Expected ciphertext: %s", hex.EncodeToString(expectedCiphertext))

	des := NewDES()
	if err := des.SetSymmetricKey(key); err != nil {
		t.Fatalf("SetSymmetricKey failed: %v", err)
	}

	// Шифруем
	ciphertext, err := des.Encrypt(plaintext)
	if err != nil {
		t.Fatalf("Encrypt failed: %v", err)
	}

	t.Logf("Got ciphertext:     %s", hex.EncodeToString(ciphertext))

	// Сравниваем
	if !bytes.Equal(ciphertext, expectedCiphertext) {
		t.Errorf("  DES encryption doesn't match known vector")
		t.Errorf("  Expected: %s", hex.EncodeToString(expectedCiphertext))
		t.Errorf("  Got:      %s", hex.EncodeToString(ciphertext))
	} else {
		t.Logf("Encryption matches known DES vector")
	}

	decrypted, err := des.Decrypt(ciphertext)
	if err != nil {
		t.Fatalf("Decrypt failed: %v", err)
	}

	t.Logf("Decrypted:         %s", hex.EncodeToString(decrypted))

	if !bytes.Equal(decrypted, plaintext) {
		t.Errorf("Decryption failed")
		t.Errorf("  Expected: %s", hex.EncodeToString(plaintext))
		t.Errorf("  Got:      %s", hex.EncodeToString(decrypted))
	} else {
		t.Logf("Decryption successful")
	}
}

// Тест на D(E(x)) == x
func TestDESEncryptDecrypt(t *testing.T) {
	tests := []struct {
		name      string
		key       string // hex
		plaintext string // hex
	}{
		{
			name:      "All zeros plaintext",
			key:       "0123456789ABCDEF",
			plaintext: "0000000000000000",
		},
		{
			name:      "All ones plaintext",
			key:       "0123456789ABCDEF",
			plaintext: "FFFFFFFFFFFFFFFF",
		},
		{
			name:      "Alternating pattern",
			key:       "0123456789ABCDEF",
			plaintext: "AAAAAAAAAAAAAAAA",
		},
		{
			name:      "Random data",
			key:       "0123456789ABCDEF",
			plaintext: "0123456789ABCDEF",
		},
		{
			name:      "ASCII message 'HELLO!!!'",
			key:       "AABB09182736CCDD",
			plaintext: "48454C4C4F212121",
		},
		{
			name:      "Another random pattern",
			key:       "133457799BBCDFF1",
			plaintext: "95F8A5E5DD31D900",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Декодируем hex
			key, err := hex.DecodeString(tt.key)
			if err != nil {
				t.Fatalf("Failed to decode key: %v", err)
			}

			plaintext, err := hex.DecodeString(tt.plaintext)
			if err != nil {
				t.Fatalf("Failed to decode plaintext: %v", err)
			}

	
			des := NewDES()
			if err := des.SetSymmetricKey(key); err != nil {
				t.Fatalf("SetSymmetricKey failed: %v", err)
			}

			// Шифруем
			ciphertext, err := des.Encrypt(plaintext)
			if err != nil {
				t.Fatalf("Encrypt failed: %v", err)
			}

			t.Logf("Key:        %s", tt.key)
			t.Logf("Plaintext:  %s", tt.plaintext)
			t.Logf("Ciphertext: %s", hex.EncodeToString(ciphertext))

			// Дешифруем
			decrypted, err := des.Decrypt(ciphertext)
			if err != nil {
				t.Fatalf("Decrypt failed: %v", err)
			}

			t.Logf("Decrypted:  %s", hex.EncodeToString(decrypted))

			// Чекаем что вернулся исходный текст
			if !bytes.Equal(decrypted, plaintext) {
				t.Errorf("Decryption failed\n  Expected: %s\n  Got:      %s",
					hex.EncodeToString(plaintext),
					hex.EncodeToString(decrypted))
			}
		})
	}
}

// Тест на размер блока
func TestDESBlockSize(t *testing.T) {
	des := NewDES()
	if des.GetBlockSize() != 8 {
		t.Errorf("Expected block size 8, got %d", des.GetBlockSize())
	}
}

// Тест на неправильне размеры ключа
func TestDESInvalidKeySize(t *testing.T) {
	des := NewDES()

	invalidKeys := [][]byte{
		{},     // Пустой
		{0x01}, // 1 байт
		{0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07},             // 7 байт
		{0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09}, // 9 байт
	}

	for _, key := range invalidKeys {
		err := des.SetSymmetricKey(key)
		if err == nil {
			t.Errorf("Expected error for key size %d, got nil", len(key))
		}
	}
}

// Тест на неправильные размеры блоков
func TestDESInvalidBlockSize(t *testing.T) {
	des := NewDES()

	// правильный ключ
	key := []byte{0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08}
	if err := des.SetSymmetricKey(key); err != nil {
		t.Fatalf("SetSymmetricKey failed: %v", err)
	}

	// неправильные размеры блоков
	invalidBlocks := [][]byte{
		{},                 // пустой
		{0x01, 0x02, 0x03}, // 3 байта
		{0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07},             // 7 байт
		{0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09}, // 9 байт
	}

	for _, block := range invalidBlocks {
		_, err := des.Encrypt(block)
		if err == nil {
			t.Errorf("Expected error for block size %d, got nil", len(block))
		}

		_, err = des.Decrypt(block)
		if err == nil {
			t.Errorf("Expected error for block size %d in Decrypt, got nil", len(block))
		}
	}
}

func TestSplitMergeCD(t *testing.T) {

	testCases := [][]byte{
		{0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0xFF, 0x11},
		{0x01, 0x23, 0x45, 0x67, 0x89, 0xAB, 0xCD},
		{0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00},
		{0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF},
	}

	for i, cd7 := range testCases {
		t.Run(hex.EncodeToString(cd7), func(t *testing.T) {
			// Разбиваем на C и D
			C, D := SplitCD(cd7)

			// чекаем их размер (28 бит)
			if C&0xF0000000 != 0 {
				t.Errorf("Test %d: C has bits outside 28-bit range: 0x%08X", i, C)
			}
			if D&0xF0000000 != 0 {
				t.Errorf("Test %d: D has bits outside 28-bit range: 0x%08X", i, D)
			}

			// Объединяем обратно
			cd7Restored := MergeCD(C, D)

			if !bytes.Equal(cd7, cd7Restored) {
				t.Errorf("Test %d: SplitCD/MergeCD roundtrip failed\n  Original:  %s\n  Restored:  %s",
					i, hex.EncodeToString(cd7), hex.EncodeToString(cd7Restored))
			}
		})
	}
}
