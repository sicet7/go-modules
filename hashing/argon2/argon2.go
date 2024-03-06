package argon2

import (
	"crypto/rand"
	"crypto/subtle"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"golang.org/x/crypto/argon2"
	"strings"
)

const (
	Argon2i  HashType = "argon2i"
	Argon2id HashType = "argon2id"
)

var (
	ErrInvalidHash         = errors.New("the encoded hash is not in the correct format")
	ErrUnsupportedType     = errors.New("unsupported hash type")
	ErrIncompatibleVersion = errors.New("incompatible version")
)

func NewParams(
	memory uint32,
	iterations uint32,
	parallelism uint8,
	saltLength uint32,
	keyLength uint32,
) Params {
	return Params{
		memory:      memory,
		iterations:  iterations,
		parallelism: parallelism,
		saltLength:  saltLength,
		keyLength:   keyLength,
	}
}

func FromPassword(hashType HashType, password string, params Params) (Hash, error) {
	salt := make([]byte, params.saltLength)
	_, err := rand.Read(salt)
	if err != nil {
		return Hash{}, err
	}
	return createArgonHash(hashType, password, salt, params)
}

func FromHash(hashString string) (Hash, error) {
	vals := strings.Split(hashString, "$")
	if len(vals) != 6 {
		return Hash{}, ErrInvalidHash
	}

	supportedTypes := map[string]HashType{
		string(Argon2i):  Argon2i,
		string(Argon2id): Argon2id,
	}

	hashType, exists := supportedTypes[vals[1]]

	if !exists {
		return Hash{}, ErrUnsupportedType
	}

	var version int
	_, err := fmt.Sscanf(vals[2], "v=%d", &version)
	if err != nil {
		return Hash{}, err
	}
	if version != argon2.Version {
		return Hash{}, ErrIncompatibleVersion
	}
	p := Params{}
	_, err = fmt.Sscanf(vals[3], "m=%d,t=%d,p=%d", &p.memory, &p.iterations, &p.parallelism)
	if err != nil {
		return Hash{}, err
	}

	var salt []byte
	salt, err = base64.RawStdEncoding.Strict().DecodeString(vals[4])
	if err != nil {
		return Hash{}, err
	}
	p.saltLength = uint32(len(salt))

	var hash []byte
	hash, err = base64.RawStdEncoding.Strict().DecodeString(vals[5])
	if err != nil {
		return Hash{}, err
	}
	p.keyLength = uint32(len(hash))

	return Hash{
		hash:     hash,
		salt:     salt,
		hashType: hashType,
		params:   p,
	}, nil
}

func (a Params) String() string {
	return fmt.Sprintf(
		"m=%d,t=%d,p=%d",
		a.memory,
		a.iterations,
		a.parallelism,
	)
}

func (a Params) Memory() uint32 {
	return a.memory
}

func (a Params) Iterations() uint32 {
	return a.iterations
}

func (a Params) Parallelism() uint8 {
	return a.parallelism
}

func (h *Hash) Type() HashType {
	return h.hashType
}

func (h *Hash) Params() Params {
	return h.params
}

func (h *Hash) String() string {
	b64Salt := base64.RawStdEncoding.EncodeToString(h.salt)
	b64Hash := base64.RawStdEncoding.EncodeToString(h.hash)
	return fmt.Sprintf(
		"$%s$v=%d$%s$%s$%s",
		h.hashType.Name(),
		argon2.Version,
		h.params.String(),
		b64Salt,
		b64Hash,
	)
}

func (h *Hash) VerifyPassword(password string) bool {
	passwordHash, err := createArgonHash(h.hashType, password, h.salt, h.params)
	if err != nil {
		return false
	}
	return subtle.ConstantTimeCompare(h.hash, passwordHash.hash) == 1
}

func (h *Hash) UnmarshalJSON(data []byte) error {
	var v string
	var hash Hash
	var err error
	if err = json.Unmarshal(data, &v); err != nil {
		return err
	}

	hash, err = FromHash(v)
	if err != nil {
		return err
	}

	h.hashType = hash.hashType
	h.params = hash.params
	h.hash = hash.hash
	h.salt = hash.salt
	return nil
}

func (h *Hash) MarshalJSON() ([]byte, error) {
	return json.Marshal(h.String())
}

func createArgonHash(
	hashType HashType,
	password string,
	salt []byte,
	params Params,
) (Hash, error) {
	var hash []byte

	if hashType.Name() == string(Argon2i) {
		hash = argon2.Key(
			[]byte(password),
			salt,
			params.iterations,
			params.memory,
			params.parallelism,
			params.keyLength,
		)
	} else if hashType.Name() == string(Argon2id) {
		hash = argon2.IDKey(
			[]byte(password),
			salt,
			params.iterations,
			params.memory,
			params.parallelism,
			params.keyLength,
		)
	} else {
		return Hash{}, ErrUnsupportedType
	}

	return Hash{
		hash:     hash,
		salt:     salt,
		hashType: hashType,
		params:   params,
	}, nil
}
