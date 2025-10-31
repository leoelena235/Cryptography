package modes

func (ctx *SymmetricContext) processPCBC(data []byte, iv []byte, isEncrypt bool) ([]byte, error) {
	result := make([]byte, len(data))
	currentIV := make([]byte, ctx.blockSize)
	copy(currentIV, iv)

	for i := 0; i < len(data); i += ctx.blockSize {
		block := make([]byte, ctx.blockSize)
		copy(block, data[i:i+ctx.blockSize])

		if isEncrypt {
			// temp = Pi XOR IV
			for j := 0; j < ctx.blockSize; j++ {
				block[j] ^= currentIV[j]
			}
			//Ci=E(K,Pi xor IVi)
			encrypted, err := ctx.cipher.Encrypt(block)
			if err != nil {
				return nil, err
			}

			copy(result[i:], encrypted)

			// IVi+1 = Pi XOR Ci, в CBC было IVi+1=Ci
			for j := 0; j < ctx.blockSize; j++ {
				currentIV[j] = data[i+j] ^ encrypted[j]
			}
		} else {
			// temp = D(K,Ci)
			decrypted, err := ctx.cipher.Decrypt(block)
			if err != nil {
				return nil, err
			}
			//Pi= D(K,Ci) XOR IVi
			plainBlock := make([]byte, ctx.blockSize)
			for j := 0; j < ctx.blockSize; j++ {
				plainBlock[j] = decrypted[j] ^ currentIV[j]
			}

			copy(result[i:], plainBlock)

			// IVi+1 = Pi XOR Ci
			for j := 0; j < ctx.blockSize; j++ {
				currentIV[j] = block[j] ^ plainBlock[j]
			}
		}
	}

	return result, nil
}
