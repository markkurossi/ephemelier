package main

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"fmt"
	"math/big"
	"os"
	"time"
)

func main() {
	// Step 1: Generate P-256 (secp256r1) key pair
	fmt.Println("Generating P-256 key pair...")
	privateKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Failed to generate private key: %v\n", err)
		os.Exit(1)
	}
	fmt.Println("✓ Key pair generated")

	// Step 2: Create self-signed certificate
	fmt.Println("\nCreating self-signed certificate...")

	// Generate a random serial number
	serialNumberLimit := new(big.Int).Lsh(big.NewInt(1), 128)
	serialNumber, err := rand.Int(rand.Reader, serialNumberLimit)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Failed to generate serial number: %v\n", err)
		os.Exit(1)
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
		DNSNames:              []string{"www.ephemelier.com"},
		NotBefore:             time.Now(),
		NotAfter:              time.Now().Add(365 * 24 * time.Hour),
		KeyUsage:              x509.KeyUsageDigitalSignature | x509.KeyUsageKeyEncipherment,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		BasicConstraintsValid: true,
		IsCA:                  false,
	}

	// Create the certificate (self-signed)
	certDER, err := x509.CreateCertificate(rand.Reader, &template, &template, &privateKey.PublicKey, privateKey)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Failed to create certificate: %v\n", err)
		os.Exit(1)
	}
	fmt.Println("✓ Certificate created")

	// Step 3: Save private key to disk
	fmt.Println("\nSaving private key to disk...")
	keyFile, err := os.Create("ephemelier-key.pem")
	if err != nil {
		fmt.Fprintf(os.Stderr, "Failed to create key file: %v\n", err)
		os.Exit(1)
	}
	defer keyFile.Close()

	// Encode private key to PKCS#8 format
	privateKeyBytes, err := x509.MarshalPKCS8PrivateKey(privateKey)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Failed to marshal private key: %v\n", err)
		os.Exit(1)
	}

	if err := pem.Encode(keyFile, &pem.Block{
		Type:  "PRIVATE KEY",
		Bytes: privateKeyBytes,
	}); err != nil {
		fmt.Fprintf(os.Stderr, "Failed to encode private key: %v\n", err)
		os.Exit(1)
	}
	fmt.Println("✓ Private key saved to: ephemelier-key.pem")

	// Step 4: Save certificate to disk
	fmt.Println("\nSaving certificate to disk...")
	certFile, err := os.Create("ephemelier-cert.pem")
	if err != nil {
		fmt.Fprintf(os.Stderr, "Failed to create certificate file: %v\n", err)
		os.Exit(1)
	}
	defer certFile.Close()

	if err := pem.Encode(certFile, &pem.Block{
		Type:  "CERTIFICATE",
		Bytes: certDER,
	}); err != nil {
		fmt.Fprintf(os.Stderr, "Failed to encode certificate: %v\n", err)
		os.Exit(1)
	}
	fmt.Println("✓ Certificate saved to: ephemelier-cert.pem")

	// Display certificate information
	cert, err := x509.ParseCertificate(certDER)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Failed to parse certificate: %v\n", err)
		os.Exit(1)
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

	fmt.Println("\n✓ Certificate generation complete!")
	fmt.Println("\nFiles created:")
	fmt.Println("  - ephemelier-key.pem  (Private key)")
	fmt.Println("  - ephemelier-cert.pem (Certificate)")
	fmt.Println("\nYou can test the certificate with:")
	fmt.Println("  openssl x509 -in ephemelier-cert.pem -text -noout")
	fmt.Println("  openssl ec -in ephemelier-key.pem -text -noout")
}
