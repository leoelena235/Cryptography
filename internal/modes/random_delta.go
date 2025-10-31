// как CTR но счетчик с seed

package modes

import (
	"encoding/binary"
	"fmt"
	"runtime"
	"sync"
)

func (ctx *SymmetricContext) processRandomDelta(data []byte, isEncrypt bool) ([]byte, error) {
	if ctx.blockSize <= 0 {
		return nil, fmt.Errorf("RandomDelta: invalid block size %d", ctx.blockSize)
	}

	nonce := ctx.getNonce()
	if len(nonce) >= ctx.blockSize {
		return nil, fmt.Errorf("RandomDelta: nonce length (%d) >= block size (%d)", len(nonce), ctx.blockSize)
	}

	counterBytes := ctx.blockSize - len(nonce)
	if counterBytes > 8 {
		return nil, fmt.Errorf("RandomDelta: counter size too large (%d bytes, max 8)", counterBytes)
	}

	result := make([]byte, len(data))
	blockCount := (len(data) + ctx.blockSize - 1) / ctx.blockSize
	seed := uint64(ctx.getRandomDeltaSeed())

	// ограничение на количество горутин
	maxWorkers := runtime.GOMAXPROCS(0) * 2
	if maxWorkers < 1 {
		maxWorkers = 1
	}
	sem := make(chan struct{}, maxWorkers)

	var wg sync.WaitGroup
	errCh := make(chan error, 1)

	//параллельно с блоками
	for blockIndex := 0; blockIndex < blockCount; blockIndex++ {
		offset := blockIndex * ctx.blockSize
		wg.Add(1)

		sem <- struct{}{}

		go func(blockIndex, offset int) {
			defer wg.Done()
			defer func() { <-sem }()

			// cnt_val = seed + i
			counterValue := seed + uint64(blockIndex)

			// cnt_block = nonce || cnt_val (в big-endian)
			counterBlock := make([]byte, ctx.blockSize)
			copy(counterBlock, nonce)

			var tmp [8]byte
			binary.BigEndian.PutUint64(tmp[:], counterValue)
			copy(counterBlock[len(counterBlock)-counterBytes:], tmp[8-counterBytes:])

			//Ki = E(K, cnt_block)
			keystream, err := ctx.cipher.Encrypt(counterBlock)
			if err != nil {
				select {
				case errCh <- fmt.Errorf("RandomDelta block %d: %w", blockIndex, err):
				default:
				}
				return
			}

			// Ci = Pi XOR Ki
			blockSize := ctx.blockSize
			if offset+blockSize > len(data) {
				blockSize = len(data) - offset // последний блок может быть неполный
			}
			for j := 0; j < blockSize; j++ {
				result[offset+j] = data[offset+j] ^ keystream[j]
			}
		}(blockIndex, offset)
	}

	wg.Wait()

	select {
	case err := <-errCh:
		return nil, err
	default:
		return result, nil
	}
}
