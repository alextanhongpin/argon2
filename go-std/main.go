package main

import (
	"crypto/rand"
	"crypto/subtle"
	"encoding/base64"
	"errors"
	"fmt"
	"io"
	"log"
	"strconv"
	"strings"

	"golang.org/x/crypto/argon2"
)

const (
	passwordType = "argon2"
	saltLen      = 16
	keyLen       = 32
	time         = 2
	memory       = 64 * 1024 // Default is 1024
	threads      = 2         // Set to equal max cpu
)

func generateSalt() (string, error) {
	// 	unencodedSalt := make([]byte, saltLen)
	// 	_, err := rand.Read(unencodedSalt)
	// 	if err != nil {
	// 		return "", err
	// 	}
	// 	return base64.StdEncoding.EncodeToString(unencodedSalt), nil
	salt := make([]byte, saltLen)
	n, err := io.ReadFull(rand.Reader, salt)
	if n != len(salt) || err != nil {
		return "", err
	}
	return base64.StdEncoding.EncodeToString(salt), nil
}

func generateSaltedHash(password string) (string, error) {
	if len(password) == 0 {
		return "", errors.New("password length cannot be zero")
	}
	salt, err := generateSalt()
	if err != nil {
		return "", err
	}

	unencodedPassword := argon2.Key([]byte(password), []byte(salt), time, memory, threads, keyLen)
	encodedPassword := base64.StdEncoding.EncodeToString(unencodedPassword)
	hash := fmt.Sprintf("%s$%d$%d$%d$%d$%s$%s", passwordType, time, memory, threads, keyLen, salt, encodedPassword)
	return hash, nil
}

func compareHashWithPassword(hash, password string) (bool, error) {
	if len(hash) == 0 || len(password) == 0 {
		return false, errors.New("arguments cannot be zero")
	}
	hashParts := strings.Split(hash, "$")
	time, _ := strconv.Atoi(hashParts[1])
	memory, _ := strconv.Atoi(hashParts[2])
	threads, _ := strconv.Atoi(hashParts[3])
	keyLen, _ := strconv.Atoi(hashParts[4])
	salt := hashParts[5]
	key, _ := base64.StdEncoding.DecodeString(hashParts[6])

	computedKey := argon2.Key([]byte(password), []byte(salt), uint32(time), uint32(memory), uint8(threads), uint32(keyLen))
	if subtle.ConstantTimeCompare(key, computedKey) != 1 {
		return false, errors.New("password do not match")
	}
	return true, nil
}
func main() {
	password := "hello world"
	hashedPassword, err := generateSaltedHash(password)
	if err != nil {
		log.Fatal(err)
	}
	log.Println(hashedPassword)
	match, err := compareHashWithPassword(hashedPassword, password)
	if err != nil {
		log.Fatal(err)
	}
	if match {
		log.Println("password match")
	}
}
