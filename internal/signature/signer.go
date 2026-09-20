package signature

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"encoding/pem"
	"errors"
	"fmt"
)

// KeyPair holds PEM-encoded private and public keys
type KeyPair struct {
	Algorithm     Algorithm
	PrivateKeyPEM []byte
	PublicKeyPEM  []byte
}

// GenerateKeyPair creates a new asymmetric key pair for the chosen algorithm
func GenerateKeyPair(alg Algorithm) (*KeyPair, error) {
	switch alg {
	case AlgoECDSAP256:
		priv, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
		if err != nil {
			return nil, err
		}
		privBytes, err := x509.MarshalECPrivateKey(priv)
		if err != nil {
			return nil, err
		}
		pubBytes, err := x509.MarshalPKIXPublicKey(&priv.PublicKey)
		if err != nil {
			return nil, err
		}
		return &KeyPair{
			Algorithm:     alg,
			PrivateKeyPEM: pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: privBytes}),
			PublicKeyPEM:  pem.EncodeToMemory(&pem.Block{Type: "PUBLIC KEY", Bytes: pubBytes}),
		}, nil

	case AlgoEd25519:
		pub, priv, err := ed25519.GenerateKey(rand.Reader)
		if err != nil {
			return nil, err
		}
		privBytes, err := x509.MarshalPKCS8PrivateKey(priv)
		if err != nil {
			return nil, err
		}
		pubBytes, err := x509.MarshalPKIXPublicKey(pub)
		if err != nil {
			return nil, err
		}
		return &KeyPair{
			Algorithm:     alg,
			PrivateKeyPEM: pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: privBytes}),
			PublicKeyPEM:  pem.EncodeToMemory(&pem.Block{Type: "PUBLIC KEY", Bytes: pubBytes}),
		}, nil

	case AlgoRSASHA256:
		priv, err := rsa.GenerateKey(rand.Reader, 2048)
		if err != nil {
			return nil, err
		}
		privBytes := x509.MarshalPKCS1PrivateKey(priv)
		pubBytes, err := x509.MarshalPKIXPublicKey(&priv.PublicKey)
		if err != nil {
			return nil, err
		}
		return &KeyPair{
			Algorithm:     alg,
			PrivateKeyPEM: pem.EncodeToMemory(&pem.Block{Type: "RSA PRIVATE KEY", Bytes: privBytes}),
			PublicKeyPEM:  pem.EncodeToMemory(&pem.Block{Type: "PUBLIC KEY", Bytes: pubBytes}),
		}, nil

	default:
		return nil, errors.New("unsupported algorithm")
	}
}

// SignPayload computes a digital signature over payload using the private key PEM
func SignPayload(alg Algorithm, privKeyPEM []byte, payload []byte) ([]byte, error) {
	block, _ := pem.Decode(privKeyPEM)
	if block == nil {
		return nil, errors.New("failed decoding PEM block for private key")
	}

	digest := sha256.Sum256(payload)

	switch alg {
	case AlgoECDSAP256:
		var privKey *ecdsa.PrivateKey
		var err error
		if block.Type == "EC PRIVATE KEY" {
			privKey, err = x509.ParseECPrivateKey(block.Bytes)
		} else {
			key, kErr := x509.ParsePKCS8PrivateKey(block.Bytes)
			if kErr == nil {
				var ok bool
				privKey, ok = key.(*ecdsa.PrivateKey)
				if !ok {
					err = errors.New("parsed key is not ECDSA")
				}
			} else {
				err = kErr
			}
		}
		if err != nil {
			return nil, fmt.Errorf("failed parsing ECDSA key: %w", err)
		}
		return ecdsa.SignASN1(rand.Reader, privKey, digest[:])

	case AlgoEd25519:
		key, err := x509.ParsePKCS8PrivateKey(block.Bytes)
		if err != nil {
			return nil, fmt.Errorf("failed parsing Ed25519 key: %w", err)
		}
		edKey, ok := key.(ed25519.PrivateKey)
		if !ok {
			return nil, errors.New("key is not Ed25519 private key")
		}
		return ed25519.Sign(edKey, payload), nil

	case AlgoRSASHA256:
		var privKey *rsa.PrivateKey
		var err error
		if block.Type == "RSA PRIVATE KEY" {
			privKey, err = x509.ParsePKCS1PrivateKey(block.Bytes)
		} else {
			key, kErr := x509.ParsePKCS8PrivateKey(block.Bytes)
			if kErr == nil {
				var ok bool
				privKey, ok = key.(*rsa.PrivateKey)
				if !ok {
					err = errors.New("parsed key is not RSA")
				}
			} else {
				err = kErr
			}
		}
		if err != nil {
			return nil, fmt.Errorf("failed parsing RSA key: %w", err)
		}
		return rsa.SignPKCS1v15(rand.Reader, privKey, crypto.SHA256, digest[:])

	default:
		return nil, errors.New("unsupported signing algorithm")
	}
}
