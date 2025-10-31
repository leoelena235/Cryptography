package modes

func (ctx *SymmetricContext) processCFB(data []byte, iv []byte, isEncrypt bool) ([]byte, error) {
	result := make([]byte, len(data))
	currentIV := make([]byte, ctx.blockSize)
	copy(currentIV, iv)

	for i := 0; i < len(data); i += ctx.blockSize {
		if isEncrypt {
			// Ki=E(K,IVi)
			keystream, err := ctx.cipher.Encrypt(currentIV)
			if err != nil {
				return nil, err
			}

			// Pi xor Ki =Ci
			for j := 0; j < ctx.blockSize; j++ {
				result[i+j] = data[i+j] ^ keystream[j]
			}

			// IVi+1=Ci
			copy(currentIV, result[i:i+ctx.blockSize])
		} else {
			// Ki=E(K,IVi)
			keystream, err := ctx.cipher.Encrypt(currentIV)
			if err != nil {
				return nil, err
			}

			// Ci xor Ki =Pi
			for j := 0; j < ctx.blockSize; j++ {
				result[i+j] = data[i+j] ^ keystream[j]
			}

			// IVi+1=Ci
			copy(currentIV, data[i:i+ctx.blockSize])
		}
	}

	return result, nil
}
