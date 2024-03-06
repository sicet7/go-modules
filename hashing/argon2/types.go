package argon2

type HashType string

type Params struct {
	memory      uint32
	iterations  uint32
	parallelism uint8
	saltLength  uint32
	keyLength   uint32
}

type Hash struct {
	hashType HashType
	hash     []byte
	salt     []byte
	params   Params
}

func (ht HashType) Name() string {
	return string(ht)
}
