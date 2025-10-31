package ciphers

// 2.1
type KeyExpansion interface {
	GenerateRoundKeys(key []byte) ([][]byte, error)
}

// 2.2
type EncryptionTransformation interface {
	Transform(inputBlock, roundKey []byte) ([]byte, error)
	GetInputBlockSize() int
	GetRoundKeySize() int
	GetOutputBlockSize() int
}

// 2.3
type SymmetricCipher interface {
	SetSymmetricKey(key []byte) error
	Encrypt(block []byte) ([]byte, error)
	Decrypt(block []byte) ([]byte, error)
	GetBlockSize() int //for des=8, deal=16
}

type CipherModeStrategy interface {
    Process(data []byte, iv []byte, isEncrypt bool) ([]byte, error)
    NeedsIV() bool
}

type CipherMode int

const (
	ECB CipherMode = iota
	CBC
	PCBC
	CFB
	OFB
	CTR
	RandomDelta
)

func (c CipherMode) String() string {
	modes := []string{"ECB", "CBC", "PCBC", "CFB", "OFB", "CTR", "RandomDelta"}
	if int(c) < 0 || int(c) >= len(modes) {
		return "Unknown"
	}
	return modes[c]
}

type PaddingMode int

const (
	Zeros    PaddingMode = iota //0
	ANSIX923                    //1
	PKCS7
	ISO10126
)

func (p PaddingMode) String() string {
	paddings := []string{"Zeros", "ANSI X.923", "PKCS7", "ISO 10126"}
	if int(p) < 0 || int(p) >= len(paddings) {
		return "Unknown"
	}
	return paddings[p]
}
