package gcm

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"golang.org/x/crypto/pbkdf2"
	"io"
	"strings"
)

func EncryptString(data []byte, key []byte) (string, error) {
	nonceAndCipherText, err := Encrypt(data, key)
	if err != nil {
		return "", err
	}
	return base64.URLEncoding.EncodeToString(nonceAndCipherText), nil
}

func DecryptString(data string, key []byte) ([]byte, error) {
	convertedData := strings.ReplaceAll(strings.ReplaceAll(data, "+", "-"), "/", "_")
	bytes, err := base64.URLEncoding.DecodeString(convertedData)
	if err != nil {
		return []byte{}, err
	}
	return Decrypt(bytes, key)
}

func Encrypt(data []byte, password []byte) ([]byte, error) {

	salt, err := generateSalt()
	if err != nil {
		return []byte{}, err
	}

	key := pbkdf2.Key(password, salt, 10000, 32, sha256.New)

	block, err1 := aes.NewCipher(key)
	if err1 != nil {
		return []byte{}, err1
	}

	iv, err2 := generateIv()
	if err2 != nil {
		return []byte{}, err2
	}

	aesgcm, err3 := cipher.NewGCM(block)
	if err3 != nil {
		return []byte{}, err3
	}

	ciphertext := aesgcm.Seal(nil, iv, data, nil)
	return append(salt, append(iv, ciphertext...)...), nil
}

func Decrypt(data []byte, password []byte) ([]byte, error) {
	salt := data[:16]
	iv := data[16:28]
	ciphertext := data[28:]

	key := pbkdf2.Key(password, salt, 10000, 32, sha256.New)

	block, err2 := aes.NewCipher(key)
	if err2 != nil {
		return []byte{}, err2
	}

	aesgcm, err3 := cipher.NewGCM(block)
	if err3 != nil {
		return []byte{}, err3
	}

	plaintext, err4 := aesgcm.Open(nil, iv, ciphertext, nil)
	if err4 != nil {
		return []byte{}, err4
	}
	return plaintext, nil
}

func generateSalt() ([]byte, error) {
	salt := make([]byte, 16)
	if _, err2 := io.ReadFull(rand.Reader, salt); err2 != nil {
		return []byte{}, err2
	}
	return salt, nil
}

func generateIv() ([]byte, error) {
	iv := make([]byte, 12)
	if _, err2 := io.ReadFull(rand.Reader, iv); err2 != nil {
		return []byte{}, err2
	}
	return iv, nil
}
