package modes

import (
	"crypto-lab/internal/ciphers"
	"errors"
	"fmt"
)

func (ctx *SymmetricContext) applyPadding(data []byte) ([]byte, error) {
	padSize := ctx.blockSize - (len(data) % ctx.blockSize) 

	if padSize == 0 { //если уже кратно
		switch ctx.paddingMode {
		case ciphers.PKCS7, ciphers.ANSIX923, ciphers.ISO10126:
			padSize = ctx.blockSize // +1 блок падинга
		case ciphers.Zeros:
			fmt.Printf("Zeros padding: data is already block-aligned, no padding added\n")
			return data, nil // тут ниче не надо
		}
	}

	padded := make([]byte, len(data)+padSize)
	copy(padded, data)

	switch ctx.paddingMode {
	case ciphers.Zeros:
		//уже нули в make

	case ciphers.PKCS7: //каждый байт паддинга = размер паддинга
		for i := len(data); i < len(padded); i++ {
			padded[i] = byte(padSize)
		}

	case ciphers.ISO10126: //случайные байты + размер паддинга = размер паддинга
		randomBytes, err := GenerateRandomBytes(padSize - 1)
		if err != nil {
			return nil, err
		}
		copy(padded[len(data):len(data)+padSize-1], randomBytes)
		padded[len(padded)-1] = byte(padSize)

	case ciphers.ANSIX923: //все нули, кроме последнего байта = размер паддинга
		for i := len(data); i < len(padded)-1; i++ {
			padded[i] = 0x00
		}
		padded[len(padded)-1] = byte(padSize)

	default:
		return nil, fmt.Errorf("unknown padding mode: %v", ctx.paddingMode)
	}

	fmt.Printf("Applied %s padding: %d bytes added\n", ctx.paddingMode, padSize)
	return padded, nil
}

func (ctx *SymmetricContext) removePadding(data []byte) ([]byte, error) {
	if len(data) == 0 {
		return nil, errors.New("data is empty")
	}

	var padSize int

	switch ctx.paddingMode {
	case ciphers.Zeros: //ищем с конца первые не нулевые байты
		lastNonZero := len(data) - 1
		for lastNonZero >= 0 && data[lastNonZero] == 0 {
			lastNonZero--
		}
		if lastNonZero < len(data)-1 { //нашли? - ура паддинг
			padSize = len(data) - lastNonZero - 1
			fmt.Printf("Padding removed: %s mode, %d bytes\n", ctx.paddingMode, padSize)
			return data[:lastNonZero+1], nil
		}

		return data, nil

	case ciphers.PKCS7, ciphers.ANSIX923, ciphers.ISO10126: //тут последний байт - размер паддинга
		padSize = int(data[len(data)-1])
		if padSize == 0 || padSize > ctx.blockSize || len(data) < padSize {
			return nil, fmt.Errorf("invalid padding size: %d", padSize)
		}

		if ctx.paddingMode == ciphers.PKCS7 {
			for i := len(data) - padSize; i < len(data); i++ {
				if data[i] != byte(padSize) {
					return nil, errors.New("invalid PKCS7 padding")
				}
			}
		} else if ctx.paddingMode == ciphers.ANSIX923 {
			for i := len(data) - padSize; i < len(data)-1; i++ {
				if data[i] != 0x00 {
					return nil, errors.New("invalid ANSI X.923 padding")
				}
			}
			// последний байт не чекаем, выше чекнули пупупу
		}

	default:
		return nil, fmt.Errorf("unknown padding mode: %v", ctx.paddingMode)
	}

	fmt.Printf("Padding removed: %s mode, %d bytes\n", ctx.paddingMode, padSize)
	return data[:len(data)-padSize], nil
}
