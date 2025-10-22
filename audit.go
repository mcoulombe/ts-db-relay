package main

import (
	"bytes"
	"fmt"
	"os"
	"path/filepath"
	"time"
)

// createAuditFile creates a new audit log file for a database session
func createAuditFile(user, machine, dbType, dbHost, database, dbUser string) (*os.File, error) {
	// Create unique audit file for this session
	// Format: {timestamp}-{dbUser}.log
	timestamp := time.Now().Format("20060102-150405")
	auditFilename := fmt.Sprintf("%s-%s.log", timestamp, dbUser)
	auditPath := filepath.Join("/var/lib/audits", auditFilename)

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

// flushAuditBuffer writes the accumulated audit buffer to file as a single entry
func flushAuditBuffer(auditFile *os.File, buffer *bytes.Buffer, startTime time.Time) {
	if buffer.Len() == 0 {
		return
	}

	data := buffer.Bytes()
	queryText := extractQueryText(data)

	if queryText != "" {
		fmt.Fprintf(auditFile, "[%s]: %s\n", startTime.Format("15:04:05.000"), queryText)
	}

	buffer.Reset()
}
