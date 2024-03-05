package main

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/pem"
	"fmt"
	"os"
)

func main() {
	// Check if the required command-line arguments are provided
	if len(os.Args) != 3 {
		fmt.Println("Usage: go run main.go <key_location> <key_name>")
		return
	}

	// Extract the command-line arguments
	keyLocation := os.Args[1]
	keyName := os.Args[2]

	// Generate a new RSA keypair
	privateKey, err := generatePrivateKey()
	if err != nil {
		fmt.Println("Failed to generate private key:", err)
		return
	}

	// Extract the public key from the private key
	publicKey := &privateKey.PublicKey

	// Save the private key to a file
	err = savePrivateKey(privateKey, keyLocation, keyName)
	if err != nil {
		fmt.Println("Failed to save private key:", err)
		return
	}

	// Save the public key to a file
	err = savePublicKey(publicKey, keyLocation, keyName)
	if err != nil {
		fmt.Println("Failed to save public key:", err)
		return
	}

	fmt.Println("Keypair generated successfully!")
}

func generatePrivateKey() (*rsa.PrivateKey, error) {
	privateKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		return nil, err
	}
	return privateKey, nil
}

func savePrivateKey(privateKey *rsa.PrivateKey, keyLocation, keyName string) error {
	privateKeyPEM := &pem.Block{
		Type:  "RSA PRIVATE KEY",
		Bytes: x509.MarshalPKCS1PrivateKey(privateKey),
	}
	privateKeyFile, err := os.Create(fmt.Sprintf("%s/%s_private_key.pem", keyLocation, keyName))
	if err != nil {
		return err
	}
	defer privateKeyFile.Close()
	pem.Encode(privateKeyFile, privateKeyPEM)
	return nil
}

func savePublicKey(publicKey *rsa.PublicKey, keyLocation, keyName string) error {
	publicKeyPEM := &pem.Block{
		Type:  "RSA PUBLIC KEY",
		Bytes: x509.MarshalPKCS1PublicKey(publicKey),
	}
	publicKeyFile, err := os.Create(fmt.Sprintf("%s/%s_public_key.pem", keyLocation, keyName))
	if err != nil {
		return err
	}
	defer publicKeyFile.Close()
	pem.Encode(publicKeyFile, publicKeyPEM)
	return nil
}