package models

import (
	"net"
	"time"
)

// NodeStatus represents the current status of a node
type NodeStatus string

const (
	NodeStatusPending NodeStatus = "pending"
	NodeStatusOnline  NodeStatus = "online"
	NodeStatusOffline NodeStatus = "offline"
	NodeStatusExpired NodeStatus = "expired"
)

// Network represents a VPN network (Hub configuration)
type Network struct {
	ID               string    `json:"id"`
	Name             string    `json:"name"`
	CIDR             string    `json:"cidr"`
	ServerPrivateKey string    `json:"-"`                           // Hub's private key (never sent to client)
	ServerPublicKey  string    `json:"server_public_key,omitempty"` // Hub's public key (sent to peers)
	ServerEndpoint   string    `json:"server_endpoint,omitempty"`   // Hub's endpoint (IP:Port)
	ListenPort       int       `json:"listen_port"`                 // UDP port (e.g., 51820)
	InterfaceName    string    `json:"interface_name"`              // Interface name (e.g., wg0)
	CreatedAt        time.Time `json:"created_at"`
	UpdatedAt        time.Time `json:"updated_at"`
}

// Node represents a peer (spoke) in the VPN network
type Node struct {
	ID        string            `json:"id"`
	NetworkID string            `json:"network_id"`
	Name      string            `json:"name"`
	VirtualIP net.IP            `json:"virtual_ip"`
	PublicKey string            `json:"public_key"`
	Labels    map[string]string `json:"labels"`
	Status    NodeStatus        `json:"status"`
	LastSeen  time.Time         `json:"last_seen"`
	PublicIP  string            `json:"public_ip,omitempty"`
	TransferRx int64            `json:"transfer_rx,omitempty"`
	TransferTx int64            `json:"transfer_tx,omitempty"`
	ExpiresAt *time.Time        `json:"expires_at,omitempty"`
	NodeInfo  *NodeInfo         `json:"node_info,omitempty"`
	Endpoints []string          `json:"endpoints"`
	CreatedAt time.Time         `json:"created_at"`
}

// NodeInfo contains metadata about the node's system
type NodeInfo struct {
	OS           string `json:"os"`
	Architecture string `json:"arch"`
	Hostname     string `json:"hostname"`
}

// User represents a system user (admin)
type User struct {
	ID           string    `json:"id"`
	Username     string    `json:"username"`
	PasswordHash string    `json:"-"`
	CreatedAt    time.Time `json:"created_at"`
}

// NetworkEvent represents a real-time network event
type NetworkEvent struct {
	Type      EventType `json:"type"`
	Payload   any       `json:"payload"`
	Timestamp time.Time `json:"timestamp"`
}

// EventType represents the type of network event
type EventType string

const (
	EventTypePeerAdded   EventType = "peer_added"
	EventTypePeerRemoved EventType = "peer_removed"
	EventTypePeerUpdated EventType = "peer_updated"
)

// VPNFirewallRule represents a firewall rule for VPN traffic control
type VPNFirewallRule struct {
	ID              string    `json:"id"`
	Name            string    `json:"name"`
	Description     string    `json:"description,omitempty"`
	
	// Source configuration
	SourceType      string    `json:"source_type"`       // any, network, node, custom
	SourceNetworkID *string   `json:"source_network_id,omitempty"`
	SourceNodeID    *string   `json:"source_node_id,omitempty"`
	SourceIP        string    `json:"source_ip,omitempty"`
	
	// Destination configuration
	DestType        string    `json:"dest_type"`         // any, network, node, custom
	DestNetworkID   *string   `json:"dest_network_id,omitempty"`
	DestNodeID      *string   `json:"dest_node_id,omitempty"`
	DestIP          string    `json:"dest_ip,omitempty"`
	
	// Rule details
	Protocol        string    `json:"protocol"`          // tcp, udp, icmp, all
	Port            string    `json:"port,omitempty"`    // port or range
	Action          string    `json:"action"`            // accept, drop, reject
	
	// Metadata
	Priority        int       `json:"priority"`
	Enabled         bool      `json:"enabled"`
	CreatedAt       time.Time `json:"created_at"`
	UpdatedAt       time.Time `json:"updated_at"`
	
	// Joined fields for display (not stored in DB)
	SourceNetworkName string  `json:"source_network_name,omitempty"`
	SourceNodeName    string  `json:"source_node_name,omitempty"`
	DestNetworkName   string  `json:"dest_network_name,omitempty"`
	DestNodeName      string  `json:"dest_node_name,omitempty"`
}

// FirewallAuditLog represents an audit log entry for firewall changes
type FirewallAuditLog struct {
	ID        string                 `json:"id"`
	Action    string                 `json:"action"`
	Details   map[string]interface{} `json:"details,omitempty"`
	UserIP    string                 `json:"user_ip,omitempty"`
	CreatedAt time.Time              `json:"created_at"`
}
