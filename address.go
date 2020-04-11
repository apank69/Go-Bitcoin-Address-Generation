package main

import (
	"crypto/sha256"
	"fmt"
	"github.com/btcsuite/btcutil/base58"
	"github.com/decred/dcrd/dcrec/secp256k1"
	"golang.org/x/crypto/ripemd160"
)

func main() {
	privKey, err := secp256k1.GeneratePrivateKey()
	pubkey := privKey.PubKey()
	x := pubkey.X()
	y := pubkey.Y()
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
	fmt.Println("Private Key:", generateWIF(privKey.Key))
	fmt.Println(privKey.Key)
	fmt.Println("Address:", address)
}

func generateChecksum(keyHash []byte) []byte {
	firstHash := sha256.Sum256(keyHash)
	firstHashSlice := firstHash[:]
	doubleHash := sha256.Sum256(firstHashSlice)
	return doubleHash[0:4]
}

func generateWIF(privkey secp256k1.ModNScalar) string {
	privkeySlice := privkey.Bytes()
	joined := []byte{}
	joined = append([]byte{0x80}, privkeySlice[:]...)
	checksum := generateChecksum(joined)
	joined = append(joined, checksum...)
	WIF := base58.Encode(joined)
	return WIF
}
