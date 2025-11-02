package main

import (
	"fmt"
	"os"
	"path/filepath"
	"time"
)

// TODO POC using a local file, move to tsrecorder and investigate standard DB audit formats

// createAuditFile creates a new audit log file for a database session
func createAuditFile(user, machine, dbType, dbHost, database, dbUser string) (*os.File, error) {
	// Create unique audit file for this session
	// Format: {timestamp}-{dbUser}.log
	timestamp := time.Now().Format("20060102-150405")
	auditFilename := fmt.Sprintf("%s-%s.log", timestamp, dbUser)

	auditDir := fmt.Sprintf("/var/lib/%s-audits", dbType)
	auditPath := filepath.Join(auditDir, auditFilename)

	auditFile, err := os.Create(auditPath)
	if err != nil {
		return nil, fmt.Errorf("failed to create audit file: %v", err)
	}

	// Write session header to audit file
	fmt.Fprintf(auditFile, "SESSION START: %s\n", time.Now().Format(time.RFC3339))
	fmt.Fprintf(auditFile, "Client: %s@%s\n", user, machine)
	fmt.Fprintf(auditFile, "Database: %s://%s/%s\n", dbType, dbHost, database)
	fmt.Fprintf(auditFile, "DB User: %s\n", dbUser)
	fmt.Fprintf(auditFile, "--- DATA START ---\n")

	return auditFile, nil
}

func auditQuery(auditFile *os.File, query string) {
	timestamp := time.Now().Format("2006-01-02 15:04:05.000")
	fmt.Fprintf(auditFile, "[%s] %s\n", timestamp, query)
}
