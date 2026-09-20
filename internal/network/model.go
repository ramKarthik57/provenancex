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

// DNSQueryRecord represents an observed DNS request (UDP port 53, DoH, or DNS-Client ETW)
type DNSQueryRecord struct {
	Timestamp   time.Time `json:"timestamp"`
	PID         int       `json:"pid,omitempty"`
	ProcessName string    `json:"processName,omitempty"`
	QueryDomain string    `json:"queryDomain"`
	QueryType   string    `json:"queryType"` // A, AAAA, TXT, CNAME, etc.
	Resolver    string    `json:"resolver"`
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
	DNSQueries        []*DNSQueryRecord   `json:"dnsQueries,omitempty"`
	IsPolicyCompliant bool                `json:"isPolicyCompliant"`
}
