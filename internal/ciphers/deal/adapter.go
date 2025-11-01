package deal

import (
	"fmt"

	"crypto-lab/internal/ciphers"
	"crypto-lab/internal/ciphers/des"
)

type DESAdapter struct {
	desCipher *des.DESCipher
}

func NewDESAdapter() *DESAdapter {
	return &DESAdapter{
		desCipher: des.NewDES(),
	}
}

func (d *DESAdapter) Transform(inputBlock, roundKey []byte) ([]byte, error) {
	if len(inputBlock) != 8 {
		return nil, fmt.Errorf("invalid input block (%d)", len(inputBlock))
	}
	if len(roundKey) != 8 {
		return nil, fmt.Errorf("invalid round key (%d)", len(roundKey))
	}

	if err := d.desCipher.SetSymmetricKey(roundKey); err != nil {
		return nil, err
	}

	return d.desCipher.Encrypt(inputBlock)
}

func (d *DESAdapter) GetInputBlockSize() int  { return 8 }
func (d *DESAdapter) GetRoundKeySize() int    { return 8 }
func (d *DESAdapter) GetOutputBlockSize() int { return 8 }

var _ ciphers.EncryptionTransformation = (*DESAdapter)(nil)
