package bcrypt

import (
	"fmt"
	"regexp"
	"testing"
)

const testHash = "$2y$12$YL07vqXL41V/i6me45MBo.seJUTBkm6F0FrmGv7p9vVR8OtJxyC1S"
const testPassword = "testing123"

func TestFromHash(t *testing.T) {
	_, err := FromHash(testHash)
	if err != nil {
		t.Fatalf("FromHash(\"%s\") failed with error: %v", testHash, err)
	}
}

func TestFromPassword(t *testing.T) {
	cost := 12
	hash, err := FromPassword(testPassword, cost)
	if err != nil {
		t.Fatalf("FromPassword(\"%s\", %d) failed with error: %v", testPassword, cost, err)
	}

	regex := fmt.Sprintf("^\\$2a\\$%d\\$.+$", cost)
	m, err1 := regexp.MatchString(regex, hash.String())

	if err1 != nil {
		t.Fatalf("Regex check failed with error: %v", err1)
	}

	if !m {
		t.Fatalf("String representation of hash did not match regex: \"%s\"", regex)
	}
}

func TestHash_VerifyPassword(t *testing.T) {
	hash, err := FromHash(testHash)
	if err != nil {
		t.Fatalf("FromHash(\"%s\") failed with error: %v", testHash, err)
	}

	val1 := hash.VerifyPassword(testPassword)
	val2 := hash.VerifyPassword("password123")
	if !val1 {
		t.Fatalf("hash.VerifyPassword(\"%s\") returned false expected true", testPassword)
	}
	if val2 {
		t.Fatalf("hash.VerifyPassword(\"%s\") returned true expected false", "password123")
	}
}
