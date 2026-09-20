package network

import "time"

// ConnectionRecord represents an observed network connection during a build
type ConnectionRecord struct {
	Timestamp   time.Time `json:"timestamp"`
	PID         int       `json:"pid,omitempty"`
	ProcessName string    `json:"processName,omitempty"`
	Protocol    string    `json:"protocol"`
	LocalAddr   string    `json:"localAddr"`
	RemoteAddr  string    `json:"remoteAddr"`
	Destination string    `json:"destination"` // Hostname or IP
	Port        int       `json:"port"`
	IsAllowed   bool      `json:"isAllowed"`
	AlertReason string    `json:"alertReason,omitempty"`
}

// Evaluation represents the complete network policy audit for a build
type Evaluation struct {
	TotalConnections  int                 `json:"totalConnections"`
	AllowedCount      int                 `json:"allowedCount"`
	ViolationCount    int                 `json:"violationCount"`
	Connections       []*ConnectionRecord `json:"connections"`
	Violations        []*ConnectionRecord `json:"violations"`
	IsPolicyCompliant bool                `json:"isPolicyCompliant"`
}
