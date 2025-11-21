package internal

import (
	"fmt"

	"github.com/xdg-go/scram"
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
