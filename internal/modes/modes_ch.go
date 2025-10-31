package modes

import (
    "crypto-lab/internal/ciphers"
    "fmt"
)


type ecbStrategy struct{ ctx *SymmetricContext }
func (s *ecbStrategy) Process(data []byte, iv []byte, isEncrypt bool) ([]byte, error) {
    return s.ctx.processECB(data, isEncrypt)
}
func (s *ecbStrategy) NeedsIV() bool { return false }

type cbcStrategy struct{ ctx *SymmetricContext }
func (s *cbcStrategy) Process(data []byte, iv []byte, isEncrypt bool) ([]byte, error) {
    return s.ctx.processCBC(data, iv, isEncrypt)
}
func (s *cbcStrategy) NeedsIV() bool { return true }

type pcbcStrategy struct{ ctx *SymmetricContext }
func (s *pcbcStrategy) Process(data []byte, iv []byte, isEncrypt bool) ([]byte, error) {
    return s.ctx.processPCBC(data, iv, isEncrypt)
}
func (s *pcbcStrategy) NeedsIV() bool { return true }

type cfbStrategy struct{ ctx *SymmetricContext }
func (s *cfbStrategy) Process(data []byte, iv []byte, isEncrypt bool) ([]byte, error) {
    return s.ctx.processCFB(data, iv, isEncrypt)
}
func (s *cfbStrategy) NeedsIV() bool { return true }

type ofbStrategy struct{ ctx *SymmetricContext }
func (s *ofbStrategy) Process(data []byte, iv []byte, isEncrypt bool) ([]byte, error) {
    return s.ctx.processOFB(data, iv, isEncrypt)
}
func (s *ofbStrategy) NeedsIV() bool { return true }

type ctrStrategy struct{ ctx *SymmetricContext }
func (s *ctrStrategy) Process(data []byte, iv []byte, isEncrypt bool) ([]byte, error) {
    return s.ctx.processCTR(data, isEncrypt)
}
func (s *ctrStrategy) NeedsIV() bool { return true }

type randomDeltaStrategy struct{ ctx *SymmetricContext }
func (s *randomDeltaStrategy) Process(data []byte, iv []byte, isEncrypt bool) ([]byte, error) {
    return s.ctx.processRandomDelta(data, isEncrypt)
}
func (s *randomDeltaStrategy) NeedsIV() bool { return false }


func (ctx *SymmetricContext) createModeStrategy() (ciphers.CipherModeStrategy, error) {
    switch ctx.cipherMode {
    case ciphers.ECB:
        return &ecbStrategy{ctx: ctx}, nil
    case ciphers.CBC:
        return &cbcStrategy{ctx: ctx}, nil
    case ciphers.PCBC:
        return &pcbcStrategy{ctx: ctx}, nil
    case ciphers.CFB:
        return &cfbStrategy{ctx: ctx}, nil
    case ciphers.OFB:
        return &ofbStrategy{ctx: ctx}, nil
    case ciphers.CTR:
        return &ctrStrategy{ctx: ctx}, nil
    case ciphers.RandomDelta:
        return &randomDeltaStrategy{ctx: ctx}, nil
    default:
        return nil, fmt.Errorf("unsupported cipher mode: %v", ctx.cipherMode)
    }
}
