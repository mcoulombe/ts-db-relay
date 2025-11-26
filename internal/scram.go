package internal

import (
	"crypto/hmac"
	"crypto/sha256"
	"fmt"

	"github.com/xdg-go/scram"
	"golang.org/x/crypto/pbkdf2"
)

const (
	scramIterations      = 4096
	scramSHA256KeyLength = 32
)

// TODO(max) abstract more of the SCRAM logic when we fully test Postgres with SCRAM auth
type SCRAMConversation struct {
	conv *scram.ClientConversation
}

func NewSCRAMConversation(username, password string) (*SCRAMConversation, error) {
	scramClient, err := scram.SHA256.NewClient(username, password, "")
	if err != nil {
		return nil, fmt.Errorf("creating SCRAM client: %w", err)
	}

	return &SCRAMConversation{
		conv: scramClient.NewConversation(),
	}, nil
}

func (s *SCRAMConversation) ClientFirst() (string, error) {
	clientFirst, err := s.conv.Step("")
	if err != nil {
		return "", fmt.Errorf("SCRAM step 1 (client-first): %w", err)
	}
	return clientFirst, nil
}

func (s *SCRAMConversation) ClientFinal(serverFirst string) (string, error) {
	clientFinal, err := s.conv.Step(serverFirst)
	if err != nil {
		return "", fmt.Errorf("SCRAM step 2 (client-final): %w", err)
	}
	return clientFinal, nil
}

func (s *SCRAMConversation) VerifyServerFinal(serverFinal string) error {
	_, err := s.conv.Step(serverFinal)
	if err != nil {
		return fmt.Errorf("SCRAM step 3 (verify server): %w", err)
	}
	return nil
}

// ExtractUsernameFromSASL extracts the username from a SCRAM-SHA-256 client-first message.
// It uses the scram library's server-side parsing by creating a temporary server conversation
// that captures the username via its credential lookup callback.
func ExtractUsernameFromSASL(payload []byte) (string, error) {
	var extractedUsername string

	server, err := scram.SHA256.NewServer(func(username string) (scram.StoredCredentials, error) {
		extractedUsername = username
		return scram.StoredCredentials{}, fmt.Errorf("username extraction only")
	})
	if err != nil {
		return "", fmt.Errorf("creating SCRAM server for parsing: %w", err)
	}

	conv := server.NewConversation()
	_, _ = conv.Step(string(payload))

	if extractedUsername == "" {
		return "", fmt.Errorf("username not found in SASL payload")
	}

	return extractedUsername, nil
}

// GenerateSCRAMCredentials generates SCRAM-SHA-256 stored credentials for the given username.
// The password value is irrelevant for the relay because authn/z is based on Tailscale identity.
// The contract with the client is to use the username as the password so the relay can generate
// SCRAM server responses the clients accept.
func GenerateSCRAMCredentials(username string) (scram.StoredCredentials, error) {
	password := username
	salt := []byte(fmt.Sprintf("%s-salt", username))

	saltedPassword := pbkdf2.Key([]byte(password), salt, scramIterations, scramSHA256KeyLength, sha256.New)

	clientKeyHmac := hmac.New(sha256.New, saltedPassword)
	clientKeyHmac.Write([]byte("Client Key"))
	clientKey := clientKeyHmac.Sum(nil)

	storedKeyHash := sha256.Sum256(clientKey)

	serverKeyHmac := hmac.New(sha256.New, saltedPassword)
	serverKeyHmac.Write([]byte("Server Key"))
	serverKey := serverKeyHmac.Sum(nil)

	return scram.StoredCredentials{
		KeyFactors: scram.KeyFactors{
			Salt:  string(salt),
			Iters: scramIterations,
		},
		StoredKey: storedKeyHash[:],
		ServerKey: serverKey,
	}, nil
}
