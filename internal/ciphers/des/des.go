package des

import (
	"fmt"

	"crypto-lab/internal/ciphers"
	feistel "crypto-lab/internal/ciphers/feistel"
	permute "crypto-lab/internal/ciphers/permute"
)

type DESCipher struct {
	feistel      *feistel.Feistel
	keyExpansion ciphers.KeyExpansion
	roundKeys    [][]byte
}

func (d *DESCipher) GetBlockSize() int {
	panic("unimplemented")
}

func NewDES() *DESCipher {
	keyExpansion := NewDESKeyExpansion()
	roundFunction := NewDESRoundFunction()

	feistelNetwork := feistel.NewFeistel(keyExpansion, roundFunction, 16)

	return &DESCipher{
		feistel:      feistelNetwork,
		keyExpansion: keyExpansion,
	}
}

func (d *DESCipher) SetSymmetricKey(key []byte) error {
	if len(key) != 8 {
		return fmt.Errorf("DES key must be 8 bytes (64 bits), got %d", len(key))
	}

	roundKeys, err := d.keyExpansion.GenerateRoundKeys(key)
	if err != nil {
		return fmt.Errorf("DES key expansion failed: %w", err)
	}

	d.roundKeys = roundKeys
	return nil
}

//	IP E IP⁻¹
func (d *DESCipher) Encrypt(block []byte) ([]byte, error) {
	if d.roundKeys == nil {
		return nil, fmt.Errorf("DES: round keys not set, call SetSymmetricKey first")
	}
	if len(block) != 8 {
		return nil, fmt.Errorf("DES: block must be 8 bytes, got %d", len(block))
	}

	// IP
	permuted, err := permute.Permute(block, DES.IP(), true, true)
	if err != nil {
		return nil, fmt.Errorf("DES IP failed: %w", err)
	}


	result, err := d.feistel.EncryptRounds(d.roundKeys, permuted)
	if err != nil {
		return nil, fmt.Errorf("DES Feistel failed: %w", err)
	}

	// IP⁻¹
	finalResult, err := permute.Permute(result, DES.IP_INV(), true, true)
	if err != nil {
		return nil, fmt.Errorf("DES IP_INV failed: %w", err)
	}

	return finalResult, nil
}


// дешифрование
func (d *DESCipher) Decrypt(block []byte) ([]byte, error) {
	if d.roundKeys == nil {
		return nil, fmt.Errorf("DES: round keys not set, call SetSymmetricKey first")
	}
	if len(block) != 8 {
		return nil, fmt.Errorf("DES: block must be 8 bytes, got %d", len(block))
	}

	//IP
	permuted, err := permute.Permute(block, DES.IP(), true, true)
	if err != nil {
		return nil, fmt.Errorf("DES IP failed: %w", err)
	}

	result, err := d.feistel.DecryptRounds(d.roundKeys, permuted)
	if err != nil {
		return nil, fmt.Errorf("DES Feistel failed: %w", err)
	}

	// IP^-1
	finalResult, err := permute.Permute(result, DES.IP_INV(), true, true)
	if err != nil {
		return nil, fmt.Errorf("DES IP_INV failed: %w", err)
	}

	return finalResult, nil
}
