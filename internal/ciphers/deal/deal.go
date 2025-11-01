package deal

import (
	"fmt"

	"crypto-lab/internal/ciphers"
	"crypto-lab/internal/ciphers/feistel"
)

type DEALCipher struct {
	keySize      int
	feistel      *feistel.Feistel
	keyExpansion ciphers.KeyExpansion
	roundKeys    [][]byte
}

func NewDEALCipher(keySize int) (*DEALCipher, error) {
	if keySize != 16 && keySize != 24 && keySize != 32 {
		return nil, fmt.Errorf("invalid deal key size (%d)", keySize)
	}

	keyExpansion, err := NewDEALKeyExpansion(keySize)
	if err != nil {
		return nil, fmt.Errorf("error: NewDEALKeyExpansion: %w", err)
	}

	roundFunction := NewDESAdapter()

	numRounds := 6
	if keySize == 32 {
		numRounds = 8
	}

	fe := feistel.NewFeistel(keyExpansion, roundFunction, numRounds)

	return &DEALCipher{
		keySize:      keySize,
		feistel:      fe,
		keyExpansion: keyExpansion,
	}, nil
}

func (d *DEALCipher) SetSymmetricKey(key []byte) error {
	if len(key) != d.keySize {
		return fmt.Errorf("error: key size mismatch: expected %d bytes, got %d", d.keySize, len(key))
	}
	roundKeys, err := d.keyExpansion.GenerateRoundKeys(key)
	if err != nil {
		return fmt.Errorf("error: key expansion: %w", err)
	}
	d.roundKeys = roundKeys
	return nil
}

func (d *DEALCipher) Encrypt(block []byte) ([]byte, error) {
	if d.roundKeys == nil {
		return nil, fmt.Errorf("error: roundKeys empty")
	}
	if len(block) != 16 {
		return nil, fmt.Errorf(" block hasn`t 16 bytes(%d)", len(block))
	}
	out, err := d.feistel.EncryptRounds(d.roundKeys, block)
	if err != nil {
		return nil, fmt.Errorf("error: Feistel encryption %w", err)
	}
	return out, nil
}

func (d *DEALCipher) Decrypt(block []byte) ([]byte, error) {
	if d.roundKeys == nil {
		return nil, fmt.Errorf("error: roundKeys empty")
	}
	if len(block) != 16 {
		return nil, fmt.Errorf(" block hasn`t 16 bytes(%d)", len(block))
	}
	out, err := d.feistel.DecryptRounds(d.roundKeys, block)
	if err != nil {
		return nil, fmt.Errorf("error: Feistel encryption %w", err)
	}
	return out, nil
}

func (d *DEALCipher) GetBlockSize() int { return 16 }

var _ ciphers.SymmetricCipher = (*DEALCipher)(nil)
