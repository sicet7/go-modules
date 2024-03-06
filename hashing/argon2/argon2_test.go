package argon2

import (
	"fmt"
	"golang.org/x/crypto/argon2"
	"regexp"
	"testing"
)

const format = "^\\$%s\\$v\\=%d\\$m\\=%d\\,t\\=%d\\,p\\=%d\\$.+\\$.+$"
const argon2Password = "testing123"
const argon2iHash = "$argon2i$v=19$m=65536,t=4,p=1$ZC9iVDJXaHZyaTMyOENzVQ$414sEr5cv8lvQoZ/UQiLDurs03HLF84eJLHAAoSPjRE"
const argon2idHash = "$argon2id$v=19$m=65536,t=4,p=1$djQ1clR0MzZ1dFJwY29BUA$yDxx2BAhqedyGTcfXGOMVtWlkNJmP/1KXG5IuOvIU30"

var (
	params Params = NewParams(65536, 1, 1, 16, 32)
)

func TestFromHashAndVerifyPasswordArgon2i(t *testing.T) {
	hash, err := FromHash(argon2iHash)
	if err != nil {
		t.Fatalf("FromHash(\"%s\") failed with error: %v", argon2iHash, err)
	}

	if hash.VerifyPassword("myPassword") {
		t.Fatalf("hash.VerifyPassword(\"%s\") returned true, expected false", "myPassword")
	}

	if !hash.VerifyPassword(argon2Password) {
		t.Fatalf("hash.VerifyPassword(\"%s\") returned false, expected true", argon2Password)
	}
}

func TestFromHashAndVerifyPasswordArgon2id(t *testing.T) {
	hash, err := FromHash(argon2idHash)
	if err != nil {
		t.Fatalf("FromHash(\"%s\") failed with error: %v", argon2idHash, err)
	}

	if hash.VerifyPassword("myPassword") {
		t.Fatalf("hash.VerifyPassword(\"%s\") returned true, expected false", "myPassword")
	}

	if !hash.VerifyPassword(argon2Password) {
		t.Fatalf("hash.VerifyPassword(\"%s\") returned false, expected true", argon2Password)
	}
}

func TestFromPasswordArgon2i(t *testing.T) {
	hash, err := FromPassword(Argon2i, argon2Password, params)
	if err != nil {
		t.Fatalf("FromPassword(\"%s\", \"%s\", %s) failed with error: %v", string(Argon2i), argon2Password, params.String(), err)
	}

	regex := fmt.Sprintf(format, string(Argon2i), argon2.Version, params.Memory(), params.Iterations(), params.Parallelism())

	m, err1 := regexp.MatchString(regex, hash.String())
	if err1 != nil {
		t.Fatalf("Regex check failed with error: %v", err1)
	}

	if !m {
		t.Fatalf("String representation of hash did not match regex: \"%s\"", regex)
	}
}

func TestFromPasswordArgon2id(t *testing.T) {
	hash, err := FromPassword(Argon2id, argon2Password, params)
	if err != nil {
		t.Fatalf("FromPassword(\"%s\", \"%s\", %s) failed with error: %v", string(Argon2id), argon2Password, params.String(), err)
	}

	regex := fmt.Sprintf(format, string(Argon2id), argon2.Version, params.Memory(), params.Iterations(), params.Parallelism())

	m, err1 := regexp.MatchString(regex, hash.String())
	if err1 != nil {
		t.Fatalf("Regex check failed with error: %v", err1)
	}

	if !m {
		t.Fatalf("String representation of hash did not match regex: \"%s\"", regex)
	}
}
