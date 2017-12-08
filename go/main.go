package main

import (
	"encoding/hex"
	"log"
	"os"

	"github.com/lhecker/argon2"
)

func main() {

	password := []byte("123456")
	cfg := argon2.DefaultConfig()
	raw, err := cfg.Hash(password, nil)
	if err != nil {
		log.Printf("Error during hashing: %s\n", err.Error())
		os.Exit(1)
	}
	log.Println(raw)
	log.Printf("Hash: %s\n", hex.EncodeToString(raw.Hash))
	log.Printf("Salt: %s\n", hex.EncodeToString(raw.Salt))
	log.Printf("Encoded: %s \n", string(raw.Encode()))

	encoded := raw.Encode()
	ok, err := argon2.VerifyEncoded(password, encoded)
	if err != nil {
		log.Printf("Error decoding hash: %s\n", err.Error())
		os.Exit(1)
	}

	log.Println("successfully decoded password", ok)

}
