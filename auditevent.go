package main

import (
	"fmt"

	"github.com/hashicorp/vault/audit"
	"github.com/prometheus/client_golang/prometheus"
)

const (
	AuditEventTypeRequest  = "request"
	AuditEventTypeResponse = "response"
)

// AuditEvent is a Vault audit log event.
type AuditEvent struct {
	entry *audit.AuditResponseEntry
}

// PromLabels generates Prometheus metric labels from an audit event.
func (a *AuditEvent) PromLabels() prometheus.Labels {
	return prometheus.Labels{
		"operation": fmt.Sprint(a.entry.Request.Operation),
		"path":      a.entry.Request.Path,
		"error":     a.entry.Error,
	}
}
