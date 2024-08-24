package gcm

import (
	"encoding/base64"
	"encoding/hex"
	"strings"
	"testing"
)

// do not use this in production!!!
const testKey = "b214cb5caea5461988c490f65970b41b"
const testData = "this is a test string"
const testDecryptKey = "tissemand"
const testDecryptSource = "This is the input text that was encrypted."
const testDecryptData = "TSd/Ul/TWkPIzDz0wudAxo8iViFtKFflcDrLu+nTsLJHr2ynHwcwhqwONxsMHz3cAz9q0S+9SEU+c5E5Xn8ubQXSFreL3vn2Dn5LP58TaWZ4HcK1ino="

func TestEncrypt(t *testing.T) {
	data := []byte(testData)
	key := []byte(testKey)
	output, err := Encrypt(data, key)
	outputString := string(output)
	if err != nil {
		t.Fatalf("Encrypt([]byte(\"%s\"), []byte(\"%s\")) failed with error %v", testData, testKey, err)
	}

	if outputString == "" {
		t.Fatalf("Encrypt([]byte(\"%s\"), []byte(\"%s\")) returned empty string", testData, testKey)
	}

	if outputString == testData || outputString == testKey {
		t.Fatalf("Encrypt([]byte(\"%s\"), []byte(\"%s\")) returned input string", testData, testKey)
	}
}

func TestEncryptString(t *testing.T) {
	data := []byte(testData)
	key := []byte(testKey)
	output, err := EncryptString(data, key)
	if err != nil {
		t.Fatalf("EncryptString([]byte(\"%s\"), []byte(\"%s\")) failed with error %v", testData, testKey, err)
	}

	if output == "" {
		t.Fatalf("EncryptString([]byte(\"%s\"), []byte(\"%s\")) returned empty string", testData, testKey)
	}

	_, err2 := base64.URLEncoding.DecodeString(output)

	if err2 != nil {
		t.Fatalf("EncryptString([]byte(\"%s\"), []byte(\"%s\")) was not valid base64: %v", testData, testKey, err2)
	}

	if output == testData || output == testKey {
		t.Fatalf("EncryptString([]byte(\"%s\"), []byte(\"%s\")) returned input string", testData, testKey)
	}
}

func TestDecrypt(t *testing.T) {
	data, err := base64.URLEncoding.DecodeString(strings.ReplaceAll(strings.ReplaceAll(testDecryptData, "+", "-"), "/", "_"))
	if err != nil {
		t.Fatalf("Failed to decode test data: %v", err)
	}

	plainData, err2 := Decrypt(data, []byte(testDecryptKey))
	if err2 != nil {
		t.Fatalf("Decrypt(%s, []byte(\"%s\")) failed to decrypt with error: %v", hex.EncodeToString(data), testDecryptKey, err2)
	}

	if string(plainData) != testDecryptSource {
		t.Fatalf("Decrypt(%s, []byte(\"%s\")) did not output expected value", hex.EncodeToString(data), testDecryptKey)
	}
}

func TestDecryptString(t *testing.T) {
	plainData, err := DecryptString(testDecryptData, []byte(testDecryptKey))
	if err != nil {
		t.Fatalf("DecryptString(%s, []byte(\"%s\")) failed to decrypt with error: %v", testDecryptData, testDecryptKey, err)
	}

	if string(plainData) != testDecryptSource {
		t.Fatalf("DecryptString(%s, []byte(\"%s\")) did not output expected value", testDecryptData, testDecryptKey)
	}
}
