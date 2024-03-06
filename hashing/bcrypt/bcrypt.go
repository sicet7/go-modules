package bcrypt

import "golang.org/x/crypto/bcrypt"

func FromHash(hash string) (Hash, error) {
	bytes := []byte(hash)
	cost, err := bcrypt.Cost(bytes)
	if err != nil {
		return Hash{}, err
	}
	params := Params{
		cost: cost,
	}
	return Hash{
		hash:   bytes,
		params: params,
	}, nil
}

func FromPassword(password string, cost int) (Hash, error) {
	bytes, err := bcrypt.GenerateFromPassword([]byte(password), cost)
	if err != nil {
		return Hash{}, err
	}
	return Hash{
		hash: bytes,
		params: Params{
			cost: cost,
		},
	}, nil
}
