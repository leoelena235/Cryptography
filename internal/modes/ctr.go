package modes

import (
	"fmt"
	"sync"
)

func (ctx *SymmetricContext) processCTR(data []byte, isEncrypt bool) ([]byte, error) {
	blockCount := (len(data) + ctx.blockSize - 1) / ctx.blockSize
	result := make([]byte, len(data))
	var wg sync.WaitGroup
	errs := make([]error, blockCount)

	nonce := ctx.getNonce()
	if len(nonce) == 0 {
		return nil, fmt.Errorf("CTR mode requires nonce parameter")
	}
	if len(nonce) > ctx.blockSize {
		return nil, fmt.Errorf("nonce too long")
	}

	// для каждого блока свой counter: nonce + индекс
	for i := 0; i < blockCount; i++ {
		wg.Add(1)
		go func(i int) { //горутиииины
			defer wg.Done()
			counter := make([]byte, ctx.blockSize)
			copy(counter, nonce)
			//счетчик - big-endian
			for j := len(nonce); j < ctx.blockSize; j++ {
				counter[j] = byte((i >> (8 * (ctx.blockSize - j - 1))) & 0xFF)
			}
			keystream, err := ctx.cipher.Encrypt(counter)
			if err != nil {
				errs[i] = err
				return
			}
			offset := i * ctx.blockSize
			blockSize := ctx.blockSize
			if offset+blockSize > len(data) {
				blockSize = len(data) - offset
			}
			xorResult, err := XOR(data[offset:offset+blockSize], keystream[:blockSize])
			if err != nil {
				errs[i] = err
				return
			}
			copy(result[offset:], xorResult)
		}(i)
	}
	wg.Wait()
	for _, err := range errs {
		if err != nil {
			return nil, err
		}
	}
	return result, nil
}
