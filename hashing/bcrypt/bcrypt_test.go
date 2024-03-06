package bcrypt

import "testing"

const testHash = "$2y$12$YL07vqXL41V/i6me45MBo.seJUTBkm6F0FrmGv7p9vVR8OtJxyC1S"
const testPassword = "testing123"

func TestFromHash(t *testing.T) {
	_, err := FromHash(testHash)
	if err != nil {
		t.Fatalf("FromHash(\"%s\") failed with error: %v", testHash, err)
	}
}

func TestFromPassword(t *testing.T) {
	_, err := FromPassword(testPassword, 12)
	if err != nil {
		t.Fatalf("FromPassword(\"%s\", 12) failed with error: %v", testPassword, err)
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
