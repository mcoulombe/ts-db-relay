package main

import (
	"encoding/json"
	"fmt"
	"strconv"
)

const tsDBDatabaseCapability = "tailscale.test/cap/databases" // TODO change to tailscale.com once added to the official list

// dbCapability represents the access grants for a specific database instance
type dbCapability struct {
	Engine string         `json:"engine,omitzero"`
	Port   int            `json:"port,omitzero"`
	Access []accessSchema `json:"access,omitzero"`
}

type accessSchema struct {
	Databases []string `json:"databases,omitzero"`
	Roles     []string `json:"roles,omitzero"`
}

// UnmarshalJSON implements custom unmarshalling for dbCapability to support
// both string and integer formats for the port field.
func (d *dbCapability) UnmarshalJSON(data []byte) error {
	// Define a temporary struct with Port as json.RawMessage
	type Alias dbCapability
	aux := &struct {
		Port json.RawMessage `json:"port,omitzero"`
		*Alias
	}{
		Alias: (*Alias)(d),
	}

	if err := json.Unmarshal(data, &aux); err != nil {
		return err
	}

	// Handle the port field - both string and int are accepted
	if len(aux.Port) > 0 {
		var portInt int
		if err := json.Unmarshal(aux.Port, &portInt); err == nil {
			d.Port = portInt
		} else {
			var portStr string
			if err := json.Unmarshal(aux.Port, &portStr); err == nil {
				port, err := strconv.Atoi(portStr)
				if err != nil {
					return fmt.Errorf("invalid port value: %v", err)
				}
				d.Port = port
			} else {
				return fmt.Errorf("port must be a string or integer")
			}
		}
	}

	return nil
}
