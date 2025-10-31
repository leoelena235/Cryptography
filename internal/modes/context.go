package modes

import (
	//	"errors"
		"fmt"
	"crypto-lab/internal/ciphers"
	"os"
	"sync"
)

type SymmetricContext struct {
	cipher      ciphers.SymmetricCipher
	blockSize   int
	cipherMode  ciphers.CipherMode
	paddingMode ciphers.PaddingMode
	iv          []byte
	params      []interface{} //доп параметры
	mu          sync.RWMutex  //for IV, при параллельных вызовах шифр/дешифр
	processor ciphers.CipherModeStrategy
}

func NewSymmetricContext(
	cipher ciphers.SymmetricCipher,
	cipherMode ciphers.CipherMode,
	paddingMode ciphers.PaddingMode,
	iv []byte,
	params ...interface{}, //для nonce и seed
)(*SymmetricContext, error){
	ctx := &SymmetricContext{
		cipher:      cipher,
		blockSize:   cipher.GetBlockSize(),
		cipherMode:  cipherMode,
		paddingMode: paddingMode,
		iv:          iv,
		params:      params,
	}
	strategy, err := ctx.createModeStrategy()
    if err != nil {
        return nil, fmt.Errorf("failed to create mode strategy: %w", err)
    }
    ctx.processor = strategy
    
    return ctx, nil
}

func (ctx *SymmetricContext) Encrypt(message []byte) ([]byte, error) {
	padded, err := ctx.applyPadding(message) //+паддинг(доп байты), чтобы кратно блоку
	if err != nil {
		return nil, err
	} //сначала добавляем паддинг, а потом процесс блок и там уже чекаем еще раз длину как раз кратна
	return ctx.processBlocks(padded, true) //тру=шифрование, первое-режим паддинга
}

func (ctx *SymmetricContext) Decrypt(ciphertext []byte) ([]byte, error) {
	decrypted, err := ctx.processBlocks(ciphertext, false) //фолз=дешифрование
	if err != nil {
		return nil, err
	}
	return ctx.removePadding(decrypted) //удаляет паддинг-возвращает исходные данные
}

func (ctx *SymmetricContext) EncryptFile(inputPath, outputPath string) error {
	data, err := os.ReadFile(inputPath)
	if err != nil {
		return err
	}
	//шифруем содержимое прочитанного файла
	encrypted, err := ctx.Encrypt(data)
	if err != nil {
		return err
	}

	return os.WriteFile(outputPath, encrypted, 0644) //записываем в новый файл
}

func (ctx *SymmetricContext) DecryptFile(inputPath, outputPath string) error {
	data, err := os.ReadFile(inputPath)
	if err != nil {
		return err
	}

	decrypted, err := ctx.Decrypt(data)
	if err != nil {
		return err
	}

	return os.WriteFile(outputPath, decrypted, 0644)
}

func (ctx *SymmetricContext) GetBlockSize() int {
	return ctx.blockSize
}
