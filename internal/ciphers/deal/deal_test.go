package deal

import (
	"bytes"
	"crypto/rand"
	"testing"
)

// 256
func TestDEAL256RoundTrip(t *testing.T) {
	deal, err := NewDEALCipher(32)
	if err != nil {
		t.Fatalf("fail to create cipher: %v", err)
	}

	key := make([]byte, 32)
	rand.Read(key)

	if err := deal.SetSymmetricKey(key); err != nil {
		t.Fatalf("fail to set key: %v", err)
	}

	plaintext := []byte("Hello World!!!!!")

	ciphertext, err := deal.Encrypt(plaintext)
	if err != nil {
		t.Fatalf("encrypt fail: %v", err)
	}

	decrypted, err := deal.Decrypt(ciphertext)
	if err != nil {
		t.Fatalf("decrypt fail: %v", err)
	}

	if !bytes.Equal(plaintext, decrypted) {
		t.Errorf("256 round-trip failed")
	}
}

func TestDEALKnownVector(t *testing.T) {
	deal, err := NewDEALCipher(16) //128
	if err != nil {
		t.Fatalf("fail to create cipher: %v", err)
	}

	key := []byte{
		0x01, 0x23, 0x45, 0x67, 0x89, 0xAB, 0xCD, 0xEF,
		0xFE, 0xDC, 0xBA, 0x98, 0x76, 0x54, 0x32, 0x10,
	}

	if err := deal.SetSymmetricKey(key); err != nil {
		t.Fatalf("fail to set key: %v", err)
	}

	plaintext := []byte("Hello world!!!!!")

	ciphertext, err := deal.Encrypt(plaintext)
	if err != nil {
		t.Fatalf("encrypt failed: %v", err)
	}

	if len(ciphertext) != 16 {
		t.Errorf("error len( %d)", len(ciphertext))
	}

	decrypted, err := deal.Decrypt(ciphertext)
	if err != nil {
		t.Fatalf("decrypt failed: %v", err)
	}

	if !bytes.Equal(plaintext, decrypted) {
		t.Errorf("round-trip fail\nexpected: %x\ngot: %x", plaintext, decrypted)
	}

	ciphertext2, err := deal.Encrypt(plaintext)
	if err != nil {
		t.Fatalf("second encrypt fail: %v", err)
	}

	if !bytes.Equal(ciphertext, ciphertext2) {
		t.Errorf("error: different ciphertexts")
	}
}
