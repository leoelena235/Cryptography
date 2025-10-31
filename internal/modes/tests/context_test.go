package modes

import (
	"bytes"
	"crypto-lab/internal/ciphers"
	"crypto-lab/internal/modes"
	"testing"
)

type mockCipherForContext struct{}

func (m *mockCipherForContext) Encrypt(block []byte) ([]byte, error) {
	result := make([]byte, len(block))
	copy(result, block)
	return result, nil
}

func (m *mockCipherForContext) Decrypt(block []byte) ([]byte, error) {
	result := make([]byte, len(block))
	copy(result, block)
	return result, nil
}

func (m *mockCipherForContext) GetBlockSize() int                { return 8 }
func (m *mockCipherForContext) SetSymmetricKey(key []byte) error { return nil }

// Тест конструктор
func TestNewSymmetricContext(t *testing.T) {
	cipher := &mockCipherForContext{}
	iv, _ := modes.GenerateRandomBytes(8)

	ctx, err := modes.NewSymmetricContext(
		cipher,
		ciphers.CBC,
		ciphers.PKCS7,
		iv,
	)

	if err != nil {
		t.Fatalf("Failed to create context: %v", err)
	}

	if ctx == nil {
		t.Fatalf("Context is nil")
	}

	if ctx.GetBlockSize() != 8 {
		t.Errorf("Block size = %d, expected 8", ctx.GetBlockSize())
	}
}

func TestNewSymmetricContextWithParams(t *testing.T) {
	cipher := &mockCipherForContext{}

	ctx, err := modes.NewSymmetricContext(
		cipher,
		ciphers.CTR,
		ciphers.PKCS7,
		nil,
		[]byte("nonce123"),
		int64(12345),
	)

	if err != nil {
		t.Fatalf("Failed to create context with params: %v", err)
	}

	if ctx == nil {
		t.Fatalf("Context is nil")
	}
}

func TestEncryptDecryptRoundTrip(t *testing.T) {
	cipher := &mockCipherForContext{}
	iv, _ := modes.GenerateRandomBytes(8)

	ctx, err := modes.NewSymmetricContext(
		cipher,
		ciphers.CBC,
		ciphers.PKCS7,
		iv,
	)
	if err != nil {
		t.Fatal(err)
	}

	testData := []byte("Hello, World!")

	encrypted, err := ctx.Encrypt(testData)
	if err != nil {
		t.Fatalf("Encryption error: %v", err)
	}

	decrypted, err := ctx.Decrypt(encrypted)
	if err != nil {
		t.Fatalf("Decryption error: %v", err)
	}

	if !bytes.Equal(testData, decrypted) {
		t.Errorf("Data mismatch:\nExpected: %v\nGot: %v", testData, decrypted)
	}
}

// Тест пустые данные
func TestEncryptEmptyData(t *testing.T) {
	cipher := &mockCipherForContext{}
	iv, _ := modes.GenerateRandomBytes(8)

	ctx, err := modes.NewSymmetricContext(
		cipher,
		ciphers.CBC,
		ciphers.PKCS7,
		iv,
	)
	if err != nil {
		t.Fatal(err)
	}

	encrypted, err := ctx.Encrypt([]byte{})
	if err != nil {
		t.Fatalf("Error encrypting empty data: %v", err)
	}

	expectedMinSize := 8
	if len(encrypted) < expectedMinSize {
		t.Errorf("Encrypted data size = %d, expected >= %d", len(encrypted), expectedMinSize)
	}
}

// Тест режимы
func TestAllCipherModes(t *testing.T) {
	cipher := &mockCipherForContext{}
	testData := []byte("TestDataForAllModes")

	modesList := []ciphers.CipherMode{
		ciphers.ECB,
		ciphers.CBC,
		ciphers.PCBC,
		ciphers.CFB,
		ciphers.OFB,
		ciphers.CTR,
		ciphers.RandomDelta,
	}

	for _, mode := range modesList {
		t.Run(mode.String(), func(t *testing.T) {
			var iv []byte
			var params []interface{}

			if mode == ciphers.CTR {
				nonce, _ := modes.GenerateRandomBytes(4)
				params = append(params, nonce)
			} else if mode == ciphers.RandomDelta {
				nonce, _ := modes.GenerateRandomBytes(4)
				seed := int64(12345)
				params = append(params, nonce, seed)
			} else {
				iv, _ = modes.GenerateRandomBytes(8)
			}

			ctx, err := modes.NewSymmetricContext(
				cipher,
				mode,
				ciphers.PKCS7,
				iv,
				params...,
			)
			if err != nil {
				t.Fatalf("Failed to create context for mode %s: %v", mode, err)
			}

			encrypted, err := ctx.Encrypt(testData)
			if err != nil {
				t.Fatalf("Encryption error in mode %s: %v", mode, err)
			}

			decrypted, err := ctx.Decrypt(encrypted)
			if err != nil {
				t.Fatalf("Decryption error in mode %s: %v", mode, err)
			}

			if !bytes.Equal(testData, decrypted) {
				t.Errorf("Mode %s: data mismatch", mode)
			}
		})
	}
}

// Тест паддинг

func TestAllPaddingModes(t *testing.T) {
	cipher := &mockCipherForContext{}
	testData := []byte("TestData")

	paddings := []ciphers.PaddingMode{
		ciphers.Zeros,
		ciphers.ANSIX923,
		ciphers.PKCS7,
		ciphers.ISO10126,
	}

	for _, padding := range paddings {
		t.Run(padding.String(), func(t *testing.T) {
			iv, _ := modes.GenerateRandomBytes(8)

			ctx, err := modes.NewSymmetricContext(
				cipher,
				ciphers.CBC,
				padding,
				iv,
			)
			if err != nil {
				t.Fatalf("Failed to create context for padding %s: %v", padding, err)
			}

			encrypted, err := ctx.Encrypt(testData)
			if err != nil {
				t.Fatalf("Encryption error with padding %s: %v", padding, err)
			}

			decrypted, err := ctx.Decrypt(encrypted)
			if err != nil {
				t.Fatalf("Decryption error with padding %s: %v", padding, err)
			}

			if !bytes.Equal(testData, decrypted) {
				t.Errorf("Padding %s: data mismatch", padding)
			}
		})
	}
}

func TestMixedModesAndPaddings(t *testing.T) {
	cipher := &mockCipherForContext{}
	testData := []byte("MixedTest123")

	combinations := []struct {
		mode    ciphers.CipherMode
		padding ciphers.PaddingMode
	}{
		{ciphers.ECB, ciphers.PKCS7},
		{ciphers.CBC, ciphers.Zeros},
		{ciphers.PCBC, ciphers.ANSIX923},
		{ciphers.CFB, ciphers.ISO10126},
		{ciphers.OFB, ciphers.PKCS7},
		{ciphers.CTR, ciphers.Zeros},
	}

	for _, combo := range combinations {
		t.Run(combo.mode.String()+"/"+combo.padding.String(), func(t *testing.T) {
			var iv []byte
			var params []interface{}

			if combo.mode == ciphers.CTR {
				nonce, _ := modes.GenerateRandomBytes(4)
				params = append(params, nonce)
			} else {
				iv, _ = modes.GenerateRandomBytes(8)
			}

			ctx, err := modes.NewSymmetricContext(
				cipher,
				combo.mode,
				combo.padding,
				iv,
				params...,
			)
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
				t.Errorf("Data mismatch")
			}
		})
	}
}

// Тест разные параметры

func TestVariousDataSizes(t *testing.T) {
	cipher := &mockCipherForContext{}

	testSizes := []int{
		1,    // 1 byte
		7,    // < block
		8,    // block
		9,    // > block
		16,   // two blocks
		100,  // many blocks
		1000, // veeery many blocks
	}

	for _, size := range testSizes {
		t.Run(("size_" + string(rune(size+'0'))), func(t *testing.T) {
			testData := make([]byte, size)
			for i := range testData {
				testData[i] = byte(i % 256)
			}

			iv, _ := modes.GenerateRandomBytes(8)
			ctx, err := modes.NewSymmetricContext(
				cipher,
				ciphers.CBC,
				ciphers.PKCS7,
				iv,
			)
			if err != nil {
				t.Fatal(err)
			}

			encrypted, err := ctx.Encrypt(testData)
			if err != nil {
				t.Fatalf("Error at size %d: %v", size, err)
			}

			decrypted, err := ctx.Decrypt(encrypted)
			if err != nil {
				t.Fatalf("Decryption error at size %d: %v", size, err)
			}

			if !bytes.Equal(testData, decrypted) {
				t.Errorf("Size %d: data mismatch", size)
			}
		})
	}
}

// Тест ошибки

func TestInvalidPaddingSize(t *testing.T) {
	cipher := &mockCipherForContext{}

	iv, _ := modes.GenerateRandomBytes(8)
	ctx, err := modes.NewSymmetricContext(
		cipher,
		ciphers.CBC,
		ciphers.PKCS7,
		iv,
	)
	if err != nil {
		t.Fatal(err)
	}

	fakeEncrypted := []byte{0, 1, 2, 3, 4, 5, 6, 7, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF}

	_, err = ctx.Decrypt(fakeEncrypted)
	if err == nil {
		t.Error("Expected error on invalid padding, but got none")
	}
}

func TestZerosPaddingEdgeCase(t *testing.T) {
	cipher := &mockCipherForContext{}

	testData := []byte("Data\x00\x00\x00") 

	iv, _ := modes.GenerateRandomBytes(8)
	ctx, err := modes.NewSymmetricContext(
		cipher,
		ciphers.CBC,
		ciphers.Zeros,
		iv,
	)
	if err != nil {
		t.Fatal(err)
	}

	encrypted, err := ctx.Encrypt(testData)
	if err != nil {
		t.Fatalf("Encryption error: %v", err)
	}

	decrypted, err := ctx.Decrypt(encrypted)
	if err != nil {
		t.Fatalf("Decryption error: %v", err)
	}

	if len(decrypted) > len(testData) {
		t.Errorf("Zeros padding: unexpected result size")
	}
}
