package bcrypt

import (
	"encoding/json"
	"golang.org/x/crypto/bcrypt"
)

type Params struct {
	cost int
}

type Hash struct {
	params Params
	hash   []byte
}

func (h *Hash) String() string {
	return string(h.hash)
}

func (h *Hash) Params() Params {
	return h.params
}

func (h *Hash) VerifyPassword(password string) bool {
	return bcrypt.CompareHashAndPassword(h.hash, []byte(password)) == nil
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

	h.params = hash.params
	h.hash = hash.hash
	return nil
}

func (h *Hash) MarshalJSON() ([]byte, error) {
	return json.Marshal(h.String())
}
