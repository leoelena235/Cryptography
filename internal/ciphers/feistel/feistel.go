package feistel

import (
	//"errors"
	"fmt"

	"crypto-lab/internal/ciphers"
	"crypto-lab/internal/modes"
)

type Feistel struct {
	keyExpansion ciphers.KeyExpansion             //интерфейс 2.1
	roundFunc    ciphers.EncryptionTransformation ///интерфейс 2.2
	roundCount   int
}

func NewFeistel(
	keyExpansion ciphers.KeyExpansion,
	roundFunc ciphers.EncryptionTransformation,
	roundCount int,
) *Feistel {
	return &Feistel{
		keyExpansion: keyExpansion,
		roundFunc:    roundFunc,
		roundCount:   roundCount,
	}
}
func (f *Feistel) EncryptRounds(roundKeys [][]byte, message []byte) ([]byte, error) {
	return f.processFeistel(message, roundKeys, false)
}

func (f *Feistel) DecryptRounds(roundKeys [][]byte, ciphertext []byte) ([]byte, error) {
	return f.processFeistel(ciphertext, roundKeys, true)
}

func (f *Feistel) Encrypt(masterKey, message []byte) ([]byte, error) {
	if f.keyExpansion == nil {
		return nil, fmt.Errorf("Feistel: keyExpansion not initialized")
	}
	if f.roundFunc == nil {
		return nil, fmt.Errorf("Feistel: roundFunc not initialized")
	}
	if f.roundCount <= 0 {
		return nil, fmt.Errorf("Feistel: roundCount must be > 0, got %d", f.roundCount)
	}

	roundKeys, err := f.keyExpansion.GenerateRoundKeys(masterKey)
	if err != nil {
		return nil, fmt.Errorf("Feistel: GenerateRoundKeys failed: %w", err)
	}

	if len(roundKeys) != f.roundCount {
		return nil, fmt.Errorf("Feistel: generated roundKeys count (%d) != roundCount (%d)",
			len(roundKeys), f.roundCount)
	}
	for i, k := range roundKeys {
		if len(k) != f.roundFunc.GetRoundKeySize() {
			return nil, fmt.Errorf("Feistel: roundKey #%d size (%d) != required (%d)",
				i, len(k), f.roundFunc.GetRoundKeySize())
		}
	}

	return f.processFeistel(message, roundKeys, false)
}

// ключи идут справа налево
func (f *Feistel) Decrypt(masterKey, ciphertext []byte) ([]byte, error) {
	if f.keyExpansion == nil {
		return nil, fmt.Errorf("Feistel: keyExpansion not initialized")
	}
	if f.roundFunc == nil {
		return nil, fmt.Errorf("Feistel: roundFunc not initialized")
	}
	if f.roundCount <= 0 {
		return nil, fmt.Errorf("Feistel: roundCount must be > 0, got %d", f.roundCount)
	}

	roundKeys, err := f.keyExpansion.GenerateRoundKeys(masterKey)
	if err != nil {
		return nil, fmt.Errorf("Feistel: GenerateRoundKeys failed: %w", err)
	}

	if len(roundKeys) != f.roundCount {
		return nil, fmt.Errorf("Feistel: generated roundKeys count (%d) != roundCount (%d)",
			len(roundKeys), f.roundCount)
	}
	for i, k := range roundKeys {
		if len(k) != f.roundFunc.GetRoundKeySize() {
			return nil, fmt.Errorf("Feistel: roundKey #%d size (%d) != required (%d)",
				i, len(k), f.roundFunc.GetRoundKeySize())
		}
	}

	return f.processFeistel(ciphertext, roundKeys, true)
}

func (f *Feistel) processFeistel(input []byte, roundKeys [][]byte, reverseRounds bool) ([]byte, error) {
	if f.roundFunc == nil {
		return nil, fmt.Errorf("Feistel: roundFunc not initialized")
	}
	if f.roundCount <= 0 {
		return nil, fmt.Errorf("Feistel: roundCount must be > 0, got %d", f.roundCount)
	}

	if len(input) == 0 {
		return nil, fmt.Errorf("Feistel: input is empty")
	}
	if len(input)%2 != 0 {
		return nil, fmt.Errorf("Feistel: input length must be even; got %d", len(input))
	}

	halfSize := len(input) / 2

	if halfSize != f.roundFunc.GetInputBlockSize() {
		return nil, fmt.Errorf("Feistel: block half size (%d) != roundFunc input size (%d)",
			halfSize, f.roundFunc.GetInputBlockSize())
	}
	if halfSize != f.roundFunc.GetOutputBlockSize() {
		return nil, fmt.Errorf("Feistel: block half size (%d) != roundFunc output size (%d)",
			halfSize, f.roundFunc.GetOutputBlockSize())
	}

	if len(roundKeys) != f.roundCount {
		return nil, fmt.Errorf("Feistel: roundKeys count (%d) != roundCount (%d)",
			len(roundKeys), f.roundCount)
	}
	for i, key := range roundKeys {
		if len(key) != f.roundFunc.GetRoundKeySize() {
			return nil, fmt.Errorf("Feistel: roundKey #%d size (%d) != required (%d)",
				i, len(key), f.roundFunc.GetRoundKeySize())
		}
	}

	permutedMessage := make([]byte, len(input))
	copy(permutedMessage, input)

	//halfSize := len(permutedMessage) / 2
	leftSide := make([]byte, halfSize)
	rightSide := make([]byte, halfSize)
	copy(leftSide, permutedMessage[:halfSize])
	copy(rightSide, permutedMessage[halfSize:])
	//РАУНДЫ ФЕЙСТЕЛЯ
	for i := 0; i < f.roundCount; i++ {
		roundIndex := i
		if reverseRounds {
			roundIndex = f.roundCount - 1 - i
		}
		//Li=Ri-1
		//Ri=Li-1 XOR F(Ri-1,Ki)
		fResult, err := f.roundFunc.Transform(rightSide, roundKeys[roundIndex])
		if err != nil {
			return nil, fmt.Errorf("Feistel: round %d failed: %w", i, err)
		}
		if len(fResult) != len(leftSide) {
			return nil, fmt.Errorf("Feistel: roundFunc output size (%d) != expected (%d)",
				len(fResult), len(leftSide))
		}

		newRight, err := modes.XOR(leftSide, fResult)
		if err != nil {
			return nil, fmt.Errorf("Feistel: XOR in round %d failed: %w", i, err)
		}
		leftSide = rightSide
		rightSide = newRight
	}
	//swap final
	result := make([]byte, len(input))
	copy(result[:halfSize], rightSide)
	copy(result[halfSize:], leftSide)

	return result, nil
}
