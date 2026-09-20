package signature

import (
	"fmt"
)

// SignerProvider models the cryptographic key storage backend
type SignerProvider string

const (
	ProviderPEM    SignerProvider = "PEM_FILE"   // Local PEM encoded key on disk
	ProviderKMS    SignerProvider = "CLOUD_KMS"  // Cloud KMS (AWS KMS / GCP Cloud KMS / Azure Key Vault)
	ProviderPKCS11 SignerProvider = "PKCS11_HSM" // Hardware Security Module (HSM) via PKCS#11
)

// PluggableSigner abstracts local and hardware-backed cryptographic signing
type PluggableSigner interface {
	Sign(digest []byte) ([]byte, error)
	Provider() SignerProvider
	PublicKeyPEM() []byte
}

// LocalPEMSigner implements PluggableSigner with on-disk PEM keys
type LocalPEMSigner struct {
	keyPair *KeyPair
}

// NewLocalPEMSigner creates a PEM-backed signer
func NewLocalPEMSigner(alg Algorithm) (*LocalPEMSigner, error) {
	kp, err := GenerateKeyPair(alg)
	if err != nil {
		return nil, err
	}
	return &LocalPEMSigner{
		keyPair: kp,
	}, nil
}

func (s *LocalPEMSigner) Sign(digest []byte) ([]byte, error) {
	return SignPayload(s.keyPair.Algorithm, s.keyPair.PrivateKeyPEM, digest)
}

func (s *LocalPEMSigner) Provider() SignerProvider {
	return ProviderPEM
}

func (s *LocalPEMSigner) PublicKeyPEM() []byte {
	return s.keyPair.PublicKeyPEM
}

// HardwareKMSSigner simulates hardware-backed cloud KMS signing
type HardwareKMSSigner struct {
	keyARN     string
	keyPair    *KeyPair
	underlying *LocalPEMSigner
}

// NewHardwareKMSSigner creates a cloud KMS signer abstraction
func NewHardwareKMSSigner(keyARN string) (*HardwareKMSSigner, error) {
	underlying, err := NewLocalPEMSigner(AlgoECDSAP256)
	if err != nil {
		return nil, err
	}
	return &HardwareKMSSigner{
		keyARN:     keyARN,
		keyPair:    underlying.keyPair,
		underlying: underlying,
	}, nil
}

func (s *HardwareKMSSigner) Sign(digest []byte) ([]byte, error) {
	if s.keyARN == "" {
		return nil, fmt.Errorf("invalid Cloud KMS Key ARN")
	}
	return s.underlying.Sign(digest)
}

func (s *HardwareKMSSigner) Provider() SignerProvider {
	return ProviderKMS
}

func (s *HardwareKMSSigner) PublicKeyPEM() []byte {
	return s.underlying.PublicKeyPEM()
}
