package main

import (
	"crypto/rand"
	"crypto/sha256"
	"fmt"
	"github.com/btcsuite/btcutil/base58"
	"github.com/decred/dcrd/dcrec/secp256k1"
	"golang.org/x/crypto/ripemd160"
)

func main() {
	_, x, y, err := secp256k1.GenerateKey(rand.Reader)
	if err != nil {
		fmt.Println(err)
	}
	ripemd := ripemd160.New()

	joined := []byte{}
	joined = append(joined, 4)
	joined = append(joined, x.Bytes()...)
	joined = append(joined, y.Bytes()...)

	hashedKeyPoints := sha256.Sum256(joined)
	hashedKeyPointsSlice := hashedKeyPoints[:]
	ripemd.Write(hashedKeyPointsSlice)
	publicKeyHash := ripemd.Sum(nil)

	publicKeyHash = append([]byte{0}, publicKeyHash...) //Prepend version Byte for Address
	checksum := generateChecksum(publicKeyHash)
	publicKeyHash = append(publicKeyHash, checksum...)
	address := base58.Encode(publicKeyHash)
	fmt.Println(address)
}

func generateChecksum(keyHash []byte) []byte {
	firstHash := sha256.Sum256(keyHash)
	firstHashSlice := firstHash[:]
	doubleHash := sha256.Sum256(firstHashSlice)
	return doubleHash[0:4]
}
