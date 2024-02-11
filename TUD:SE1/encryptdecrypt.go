package main

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"encoding/hex"
	"flag"
	"fmt"
	"io"
	"io/ioutil"
	"log"
	"os"
)

func main() {
	key1 := flag.String("key1", "", "32 byte AES key 1")
	key2 := flag.String("key2", "", "32 byte AES key 2")
	key3 := flag.String("key3", "", "32 byte AES key 3")
	flag.Parse()

	combinedKey, err := xorKeys(*key1, *key2, *key3)
	if err != nil {
		log.Fatal(err)
	}
	fmt.Printf("Combined key: %x\n", combinedKey)

	filename := "./volumes/v1/output.txt"
	plaintext, err := ioutil.ReadFile(filename)
	if err != nil {
		log.Fatal(err)
	}
	fmt.Printf("\nContents of the file before encryption:\n\n%s\n\n", string(plaintext))

	ciphertext, err := encrypt(plaintext, combinedKey)
	if err != nil {
		log.Fatal(err)
	}

	encryptedFilename := "./out/file.txt"
	err = ioutil.WriteFile(encryptedFilename, ciphertext, 0644)
	if err != nil {
		log.Fatal(err)
	}
	fmt.Printf("\nEncrypted file written to %s\n\n", encryptedFilename)

	encryptedFile, err := os.Open(encryptedFilename)
	if err != nil {
		log.Fatal(err)
	}
	defer encryptedFile.Close()

	decryptedFile, err := decrypt(encryptedFile, combinedKey)
	if err != nil {
		log.Fatal(err)
	}

	fmt.Printf("Contents of the file after encryption:\n\n\n%s\n", string(decryptedFile))
}

func xorKeys(keys ...string) ([]byte, error) {
	var combinedKey []byte
	for _, key := range keys {
		keyBytes, err := hex.DecodeString(key)
		if err != nil {
			return nil, err
		}
		if combinedKey == nil {
			combinedKey = make([]byte, len(keyBytes))
			copy(combinedKey, keyBytes)
		} else {
			for i := range combinedKey {
				combinedKey[i] ^= keyBytes[i]
			}
		}
	}
	return combinedKey, nil
}

func encrypt(plaintext []byte, key []byte) ([]byte, error) {
	iv := make([]byte, aes.BlockSize)
	if _, err := io.ReadFull(rand.Reader, iv); err != nil {
		return nil, err
	}

	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}

	ciphertext := make([]byte, aes.BlockSize+len(plaintext))
	copy(ciphertext[:aes.BlockSize], iv)
	stream := cipher.NewCFBEncrypter(block, iv)
	stream.XORKeyStream(ciphertext[aes.BlockSize:], plaintext)

	return ciphertext, nil
}

func decrypt(ciphertext io.Reader, key []byte) ([]byte, error) {
	iv := make([]byte, aes.BlockSize)
	if _, err := io.ReadFull(ciphertext, iv); err != nil {
		return nil, err
	}

	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}

	var plaintext []byte
	stream := cipher.NewCFBDecrypter(block, iv)
	buf := make([]byte, 1024)
	for {
		n, err := ciphertext.Read(buf)
		if err == io.EOF {
			break
		}
		if err != nil {
			return nil, err
		}
		stream.XORKeyStream(buf[:n], buf[:n])
		plaintext = append(plaintext, buf[:n]...)
	}

	return plaintext, nil
}
