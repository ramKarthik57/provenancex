package main

import (
	"encoding/hex"
	"encoding/json"
	"fmt"
	"os"
	"strings"

	"github.com/ramKarthik57/provenancex/internal/signature"
	"github.com/spf13/cobra"
)

var (
	signArtifactFile string
	signSigFile      string
	signKeyFile      string
	signAlgorithm    string
	signOutputFile   string
	signJSONOutput   bool
	signKeyPrefix    string
)

var signCmd = &cobra.Command{
	Use:   "sign",
	Short: "Cryptographic signing and verification for build artifacts and attestations",
	Long: `Supports standard asymmetric signature verification using ECDSA (P-256),
Ed25519, and RSA algorithms. Enforces strict distinctions between Hash, Signature,
Attestation, and Provenance records.`,
}

var signVerifyCmd = &cobra.Command{
	Use:   "verify",
	Short: "Verify a cryptographic signature against an artifact",
	RunE: func(cmd *cobra.Command, args []string) error {
		if signArtifactFile == "" || signSigFile == "" || signKeyFile == "" {
			return fmt.Errorf("--artifact, --signature, and --key flags are required")
		}

		pubPEM, err := os.ReadFile(signKeyFile)
		if err != nil {
			return fmt.Errorf("failed reading public key file: %w", err)
		}

		sigData, err := os.ReadFile(signSigFile)
		if err != nil {
			return fmt.Errorf("failed reading signature file: %w", err)
		}

		// Support hex or raw binary signature
		cleanSig := strings.TrimSpace(string(sigData))
		rawSig, hexErr := hex.DecodeString(cleanSig)
		if hexErr != nil {
			rawSig = sigData
		}

		alg := parseAlgorithm(signAlgorithm)
		verifier := signature.NewVerifier()
		res, err := verifier.VerifyFile(alg, pubPEM, signArtifactFile, rawSig)
		if err != nil {
			return err
		}

		if signJSONOutput {
			enc := json.NewEncoder(os.Stdout)
			enc.SetIndent("", "  ")
			return enc.Encode(res)
		}

		fmt.Println("=== ProvenanceX Digital Signature Verification ===")
		fmt.Printf("Artifact:    %s\n", signArtifactFile)
		fmt.Printf("Algorithm:   %s\n", res.Algorithm)
		fmt.Printf("Type:        %s\n", res.Distinction)
		if res.Valid {
			fmt.Println("Status:      SIGNATURE VALID (✓)")
		} else {
			fmt.Println("Status:      SIGNATURE INVALID (✗)")
			fmt.Printf("Details:     %s\n", res.Error)
		}

		return nil
	},
}

var signCreateCmd = &cobra.Command{
	Use:   "create",
	Short: "Sign an artifact or attestation using a private key",
	RunE: func(cmd *cobra.Command, args []string) error {
		if signArtifactFile == "" || signKeyFile == "" {
			return fmt.Errorf("--artifact and --key flags are required")
		}

		privPEM, err := os.ReadFile(signKeyFile)
		if err != nil {
			return fmt.Errorf("failed reading private key file: %w", err)
		}

		artifactData, err := os.ReadFile(signArtifactFile)
		if err != nil {
			return fmt.Errorf("failed reading artifact file: %w", err)
		}

		alg := parseAlgorithm(signAlgorithm)
		sigBytes, err := signature.SignPayload(alg, privPEM, artifactData)
		if err != nil {
			return fmt.Errorf("signing failed: %w", err)
		}

		hexSig := hex.EncodeToString(sigBytes)
		if signOutputFile != "" {
			if err := os.WriteFile(signOutputFile, []byte(hexSig), 0644); err != nil {
				return fmt.Errorf("failed writing signature file: %w", err)
			}
			fmt.Printf("Signature successfully generated and saved to: %s\n", signOutputFile)
			return nil
		}

		fmt.Println(hexSig)
		return nil
	},
}

var signKeygenCmd = &cobra.Command{
	Use:   "keygen",
	Short: "Generate asymmetric keypair (ECDSA, Ed25519, or RSA)",
	RunE: func(cmd *cobra.Command, args []string) error {
		alg := parseAlgorithm(signAlgorithm)
		kp, err := signature.GenerateKeyPair(alg)
		if err != nil {
			return fmt.Errorf("keygen failed: %w", err)
		}

		prefix := "key"
		if signKeyPrefix != "" {
			prefix = signKeyPrefix
		}

		privFile := prefix + ".priv.pem"
		pubFile := prefix + ".pub.pem"

		if err := os.WriteFile(privFile, kp.PrivateKeyPEM, 0600); err != nil {
			return fmt.Errorf("failed writing private key: %w", err)
		}
		if err := os.WriteFile(pubFile, kp.PublicKeyPEM, 0644); err != nil {
			return fmt.Errorf("failed writing public key: %w", err)
		}

		fmt.Printf("Keypair generated successfully (%s):\n", alg)
		fmt.Printf("  Private Key: %s\n", privFile)
		fmt.Printf("  Public Key:  %s\n", pubFile)
		return nil
	},
}

func parseAlgorithm(input string) signature.Algorithm {
	switch strings.ToLower(input) {
	case "ed25519":
		return signature.AlgoEd25519
	case "rsa":
		return signature.AlgoRSASHA256
	default:
		return signature.AlgoECDSAP256
	}
}

func init() {
	signVerifyCmd.Flags().StringVarP(&signArtifactFile, "artifact", "a", "", "Path to artifact file")
	signVerifyCmd.Flags().StringVarP(&signSigFile, "signature", "s", "", "Path to signature file")
	signVerifyCmd.Flags().StringVarP(&signKeyFile, "key", "k", "", "Path to public key PEM file")
	signVerifyCmd.Flags().StringVar(&signAlgorithm, "alg", "ecdsa", "Signature algorithm: ecdsa, ed25519, or rsa")
	signVerifyCmd.Flags().BoolVar(&signJSONOutput, "json", false, "Output results as formatted JSON")

	signCreateCmd.Flags().StringVarP(&signArtifactFile, "artifact", "a", "", "Path to artifact file")
	signCreateCmd.Flags().StringVarP(&signKeyFile, "key", "k", "", "Path to private key PEM file")
	signCreateCmd.Flags().StringVarP(&signOutputFile, "output", "o", "", "File path to save signature hex")
	signCreateCmd.Flags().StringVar(&signAlgorithm, "alg", "ecdsa", "Signature algorithm: ecdsa, ed25519, or rsa")

	signKeygenCmd.Flags().StringVar(&signAlgorithm, "alg", "ecdsa", "Signature algorithm: ecdsa, ed25519, or rsa")
	signKeygenCmd.Flags().StringVar(&signKeyPrefix, "prefix", "provenancex-signing-key", "Prefix for generated key files")

	signCmd.AddCommand(signVerifyCmd)
	signCmd.AddCommand(signCreateCmd)
	signCmd.AddCommand(signKeygenCmd)
	rootCmd.AddCommand(signCmd)
}
