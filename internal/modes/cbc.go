package modes

import "sync"

func (ctx *SymmetricContext) processCBC(data []byte, iv []byte, isEncrypt bool) ([]byte, error) {
	result := make([]byte, len(data))
	currentIV := make([]byte, ctx.blockSize)
	copy(currentIV, iv)

	if isEncrypt {
		for i := 0; i < len(data); i += ctx.blockSize {
			block := make([]byte, ctx.blockSize)
			copy(block, data[i:i+ctx.blockSize])

			// block=Pi XOR IV
			for j := 0; j < ctx.blockSize; j++ {
				block[j] ^= currentIV[j]
			}
			//Ci=E(K,Pi xor IVi)
			encrypted, err := ctx.cipher.Encrypt(block)
			if err != nil {
				return nil, err
			}

			copy(result[i:], encrypted)
			copy(currentIV, encrypted) // IV i+1=Ci
		}
	} else {
		// параллельный дешифр блоков, последовательно XOR
		var wg sync.WaitGroup
		decryptedBlocks := make([][]byte, len(data)/ctx.blockSize)
		errCh := make(chan error, 1)

		for i := 0; i < len(data); i += ctx.blockSize {
			wg.Add(1)
			go func(blockIndex int) {
				defer wg.Done()

				block := data[blockIndex : blockIndex+ctx.blockSize]
				decrypted, err := ctx.cipher.Decrypt(block)
				if err != nil {
					select {
					case errCh <- err:
					default:
					}
					return
				}
				decryptedBlocks[blockIndex/ctx.blockSize] = decrypted
			}(i)
		}
		wg.Wait()

		select {
		case err := <-errCh:
			return nil, err
		default:
		}

		// XOR 
		prevBlock := iv
		for i := 0; i < len(decryptedBlocks); i++ {
			//Pi=D(K,Ci) XOR IVi
			plainBlock, err := XOR(decryptedBlocks[i], prevBlock)
			if err != nil {
				return nil, err
			}
			copy(result[i*ctx.blockSize:], plainBlock)
			//IVi+1=Ci
			if i < len(data)/ctx.blockSize-1 {
				prevBlock = data[i*ctx.blockSize : (i+1)*ctx.blockSize]
			}
		}
	}

	return result, nil
}
