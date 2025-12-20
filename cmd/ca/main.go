package main

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"fmt"
	"log"
	"math/big"
	"os"
	"time"
)

func main() {
	fmt.Println("Generating P-256 key pair...")
	privateKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		log.Fatalf("Failed to generate private key: %v\n", err)
	}

	// Generate a random serial number
	serialNumberLimit := new(big.Int).Lsh(big.NewInt(1), 128)
	serialNumber, err := rand.Int(rand.Reader, serialNumberLimit)
	if err != nil {
		log.Fatalf("Failed to generate serial number: %v\n", err)
	}

	// Certificate template
	template := x509.Certificate{
		SignatureAlgorithm: x509.ECDSAWithSHA256,
		PublicKeyAlgorithm: x509.ECDSA,
		SerialNumber:       serialNumber,
		Subject: pkix.Name{
			Organization: []string{"Ephemelier"},
			Country:      []string{"FI"},
			CommonName:   "ephemelier.com",
		},
		DNSNames: []string{
			"www.ephemelier.com",
			"localhost",
		},
		NotBefore:             time.Now(),
		NotAfter:              time.Now().Add(365 * 24 * time.Hour),
		KeyUsage:              x509.KeyUsageDigitalSignature,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		BasicConstraintsValid: true,
		IsCA:                  false,
	}
	certDER, err := x509.CreateCertificate(rand.Reader, &template, &template,
		&privateKey.PublicKey, privateKey)
	if err != nil {
		log.Fatalf("Failed to create certificate: %v\n", err)
	}

	fmt.Println("\nSaving private key to disk...")
	keyFile, err := os.Create("ephemelier-key.pem")
	if err != nil {
		log.Fatalf("Failed to create key file: %v\n", err)
	}
	defer keyFile.Close()

	privateKeyBytes, err := x509.MarshalECPrivateKey(privateKey)
	if err != nil {
		log.Fatalf("Failed to marshal private key: %v\n", err)
	}

	if err := pem.Encode(keyFile, &pem.Block{
		Type:  "PRIVATE KEY",
		Bytes: privateKeyBytes,
	}); err != nil {
		log.Fatalf("Failed to encode private key: %v\n", err)
	}

	fmt.Println("\nSaving certificate to disk...")
	certFile, err := os.Create("ephemelier-cert.pem")
	if err != nil {
		log.Fatalf("Failed to create certificate file: %v\n", err)
	}
	defer certFile.Close()

	if err := pem.Encode(certFile, &pem.Block{
		Type:  "CERTIFICATE",
		Bytes: certDER,
	}); err != nil {
		log.Fatalf("Failed to encode certificate: %v\n", err)
	}

	// Display certificate information
	cert, err := x509.ParseCertificate(certDER)
	if err != nil {
		log.Fatalf("Failed to parse certificate: %v\n", err)
	}

	fmt.Println("\n" + "==================================================")
	fmt.Println("Certificate Information:")
	fmt.Println("==================================================")
	fmt.Printf("Subject: %s\n", cert.Subject)
	fmt.Printf("Issuer: %s\n", cert.Issuer)
	fmt.Printf("Serial Number: %s\n", cert.SerialNumber)
	fmt.Printf("Not Before: %s\n", cert.NotBefore.Format(time.RFC3339))
	fmt.Printf("Not After: %s\n", cert.NotAfter.Format(time.RFC3339))
	fmt.Printf("Subject Alt Names (DNS):\n")
	for _, dns := range cert.DNSNames {
		fmt.Printf("  - %s\n", dns)
	}
	fmt.Printf("Signature Algorithm: %s\n", cert.SignatureAlgorithm)
	fmt.Printf("Public Key Algorithm: %s\n", cert.PublicKeyAlgorithm)
	fmt.Println("==================================================")
}
