package modes

import (
	"runtime"
	"sync"
)

func (ctx *SymmetricContext) processECB(data []byte, isEncrypt bool) ([]byte, error) {
	blockCount := len(data) / ctx.blockSize //уже чекали убрать
	result := make([]byte, len(data))
	var wg sync.WaitGroup
	errs := make([]error, blockCount)
	maxWorkers := runtime.NumCPU() //лимит на горутины, а то печаль может быть
	sem := make(chan struct{}, maxWorkers)
	for i := 0; i < blockCount; i++ {
		sem <- struct{}{} 
		wg.Add(1)
		go func(i int) { //горутина на каждый блок
			defer wg.Done()
			defer func() { <-sem }() 
			offset := i * ctx.blockSize
			block := data[offset : offset+ctx.blockSize]
			var out []byte
			var err error
			if isEncrypt {
				out, err = ctx.cipher.Encrypt(block)
			} else {
				out, err = ctx.cipher.Decrypt(block)
			}
			if err == nil {
				copy(result[offset:], out)
			} else {
				errs[i] = err
			}
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
