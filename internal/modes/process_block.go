package modes

import (
	"errors"
	//"fmt"

	//"crypto-lab/internal/ciphers"
)

// работает с уже выровненными данными
func (ctx *SymmetricContext) processBlocks(data []byte, isEncrypt bool) ([]byte, error) {
	if len(data)%ctx.blockSize != 0 {
		return nil, errors.New("data length must be a multiple of block size")
	} //длина кратна размеру блока

	ctx.mu.RLock() //блок для чтения - много горутин  одноврм читают
	currentIV := make([]byte, ctx.blockSize)
	if ctx.iv != nil {
		copy(currentIV, ctx.iv) 
		ctx.mu.RUnlock()
	} else {
		ctx.mu.RUnlock()
		//разблок и  генерим случайный IV
		var err error
		currentIV, err = GenerateRandomBytes(ctx.blockSize)
		if err != nil {
			return nil, err
		}

		ctx.mu.Lock()     
		if ctx.iv == nil {
			ctx.iv = make([]byte, len(currentIV))
			copy(ctx.iv, currentIV)
		}
		ctx.mu.Unlock()
	}
return ctx.processor.Process(data, currentIV, isEncrypt)
}
