package rand

import (
	"testing"
)

const randomSeededSeed = "test123"
const randomSeededValue = "y_ErowNOvkHjnJZfpkLVtYKG4HTms8N3"

func TestGetSeededRandomString(t *testing.T) {
	value, err := GetSeededRandomString(randomSeededSeed, 32)

	if err != nil {
		t.Fatalf("GetSeededRandomString(\"%s\", %d) failed with error: %v", randomSeededSeed, 32, err)
	}

	if len(value) != 32 {
		t.Fatalf("GetSeededRandomString(\"%s\", %d) produced string that did not match the desired length", randomSeededSeed, 32)
	}

	if value != randomSeededValue {
		t.Fatalf("GetSeededRandomString(\"%s\", %d) did not produce expected string", randomSeededSeed, 32)
	}

	value2, err2 := GetSeededRandomString("test1234", 32)

	if err2 != nil {
		t.Fatalf("GetSeededRandomString(\"%s\", %d) failed with error: %v", "test1234", 32, err2)
	}

	if len(value) != 32 {
		t.Fatalf("GetSeededRandomString(\"%s\", %d) produced string that did not match the desired length", "test1234", 32)
	}

	if value == value2 {
		t.Fatalf("GetSeededRandomString(\"%s\", %d) produced string equal to output of GetSeededRandomString(\"%s\", %d)", "test1234", 32, randomSeededSeed, 32)
	}
}
