package store

import (
	"context"
	"database/sql"
	"encoding/json"
	"fmt"
	"net"
	"time"

	"github.com/google/uuid"
	_ "github.com/lib/pq"
	"github.com/novusgate/novusgate/internal/shared/models"
)

// Store provides database operations for the control plane
type Store struct {
	db *sql.DB
}

// New creates a new store with the given database connection string
func New(connStr string) (*Store, error) {
	db, err := sql.Open("postgres", connStr)
	if err != nil {
		return nil, fmt.Errorf("failed to open database: %w", err)
	}
	
	if err := db.Ping(); err != nil {
		return nil, fmt.Errorf("failed to ping database: %w", err)
	}
	
	// Set connection pool settings
	db.SetMaxOpenConns(25)
	db.SetMaxIdleConns(5)
	db.SetConnMaxLifetime(5 * time.Minute)
	
	return &Store{db: db}, nil
}

// Close closes the database connection
func (s *Store) Close() error {
	return s.db.Close()
}

// Network operations

// CreateNetwork creates a new network
func (s *Store) CreateNetwork(ctx context.Context, network *models.Network) error {
	if network.ID == "" {
		network.ID = uuid.New().String()
	}
	network.CreatedAt = time.Now()
	network.UpdatedAt = time.Now()
	
	_, err := s.db.ExecContext(ctx, `
		INSERT INTO networks (id, name, cidr, server_private_key, server_public_key, server_endpoint, listen_port, interface_name, created_at, updated_at)
		VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10)
	`, network.ID, network.Name, network.CIDR, network.ServerPrivateKey, network.ServerPublicKey, network.ServerEndpoint, network.ListenPort, network.InterfaceName, network.CreatedAt, network.UpdatedAt)
	
	return err
}

// GetNetwork retrieves a network by ID
func (s *Store) GetNetwork(ctx context.Context, id string) (*models.Network, error) {
	var network models.Network
	var serverPrivateKey, serverPublicKey, serverEndpoint sql.NullString
	err := s.db.QueryRowContext(ctx, `
		SELECT id, name, cidr, server_private_key, server_public_key, server_endpoint, listen_port, interface_name, created_at, updated_at
		FROM networks WHERE id = $1
	`, id).Scan(&network.ID, &network.Name, &network.CIDR, &serverPrivateKey, &serverPublicKey, &serverEndpoint, &network.ListenPort, &network.InterfaceName, &network.CreatedAt, &network.UpdatedAt)
	
	if err == sql.ErrNoRows {
		return nil, nil
	}
	network.ServerPrivateKey = serverPrivateKey.String
	network.ServerPublicKey = serverPublicKey.String
	network.ServerEndpoint = serverEndpoint.String
	return &network, err
}

// GetNetworkByName retrieves a network by name
func (s *Store) GetNetworkByName(ctx context.Context, name string) (*models.Network, error) {
	var network models.Network
	var serverPrivateKey, serverPublicKey, serverEndpoint sql.NullString
	err := s.db.QueryRowContext(ctx, `
		SELECT id, name, cidr, server_private_key, server_public_key, server_endpoint, listen_port, interface_name, created_at, updated_at
		FROM networks WHERE name = $1
	`, name).Scan(&network.ID, &network.Name, &network.CIDR, &serverPrivateKey, &serverPublicKey, &serverEndpoint, &network.ListenPort, &network.InterfaceName, &network.CreatedAt, &network.UpdatedAt)
	
	if err == sql.ErrNoRows {
		return nil, nil
	}
	network.ServerPrivateKey = serverPrivateKey.String
	network.ServerPublicKey = serverPublicKey.String
	network.ServerEndpoint = serverEndpoint.String
	return &network, err
}

// ListNetworks lists all networks
func (s *Store) ListNetworks(ctx context.Context) ([]*models.Network, error) {
	rows, err := s.db.QueryContext(ctx, `
		SELECT id, name, cidr, server_private_key, server_public_key, server_endpoint, listen_port, interface_name, created_at, updated_at
		FROM networks ORDER BY name
	`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	
	var networks []*models.Network
	for rows.Next() {
		var network models.Network
		var serverPrivateKey, serverPublicKey, serverEndpoint sql.NullString
		if err := rows.Scan(&network.ID, &network.Name, &network.CIDR, &serverPrivateKey, &serverPublicKey, &serverEndpoint, &network.ListenPort, &network.InterfaceName, &network.CreatedAt, &network.UpdatedAt); err != nil {
			return nil, err
		}
		network.ServerPrivateKey = serverPrivateKey.String
		network.ServerPublicKey = serverPublicKey.String
		network.ServerEndpoint = serverEndpoint.String
		networks = append(networks, &network)
	}
	return networks, rows.Err()
}

// DeleteNetwork deletes a network
func (s *Store) DeleteNetwork(ctx context.Context, id string) error {
	_, err := s.db.ExecContext(ctx, `DELETE FROM networks WHERE id = $1`, id)
	return err
}

// UpdateNetworkCIDR updates the CIDR of a network
func (s *Store) UpdateNetworkCIDR(ctx context.Context, id, cidr string) error {
	_, err := s.db.ExecContext(ctx, `UPDATE networks SET cidr = $1, updated_at = $2 WHERE id = $3`, cidr, time.Now(), id)
	return err
}

// UpdateNetworkKeys updates the WireGuard keys of a network
func (s *Store) UpdateNetworkKeys(ctx context.Context, id, privateKey, publicKey string) error {
	_, err := s.db.ExecContext(ctx, `
		UPDATE networks SET server_private_key = $1, server_public_key = $2, updated_at = $3 
		WHERE id = $4
	`, privateKey, publicKey, time.Now(), id)
	return err
}

// Node operations

// CreateNode creates a new node
func (s *Store) CreateNode(ctx context.Context, node *models.Node) error {
	if node.ID == "" {
		node.ID = uuid.New().String()
	}
	node.CreatedAt = time.Now()
	
	labelsJSON, _ := json.Marshal(node.Labels)
	nodeInfoJSON, _ := json.Marshal(node.NodeInfo)
	
	_, err := s.db.ExecContext(ctx, `
		INSERT INTO nodes (id, network_id, name, virtual_ip, public_key, labels, status, node_info, expires_at, created_at)
		VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10)
	`, node.ID, node.NetworkID, node.Name, node.VirtualIP.String(), node.PublicKey, 
	   labelsJSON, node.Status, nodeInfoJSON, node.ExpiresAt, node.CreatedAt)
	
	return err
}

// GetNode retrieves a node by ID
func (s *Store) GetNode(ctx context.Context, id string) (*models.Node, error) {
	var node models.Node
	var virtualIP string
	var labelsJSON, nodeInfoJSON []byte
	var lastSeen sql.NullTime
	
	err := s.db.QueryRowContext(ctx, `
		SELECT id, network_id, name, virtual_ip, public_key, labels, status, last_seen, node_info, expires_at, created_at
		FROM nodes WHERE id = $1
	`, id).Scan(&node.ID, &node.NetworkID, &node.Name, &virtualIP, &node.PublicKey,
		&labelsJSON, &node.Status, &lastSeen, &nodeInfoJSON, &node.ExpiresAt, &node.CreatedAt)
	
	if err == sql.ErrNoRows {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	
	node.VirtualIP = net.ParseIP(virtualIP)
	if lastSeen.Valid {
		node.LastSeen = lastSeen.Time
	}
	json.Unmarshal(labelsJSON, &node.Labels)
	json.Unmarshal(nodeInfoJSON, &node.NodeInfo)
	
	return &node, nil
}

// GetNodeByName retrieves a node by network and name
func (s *Store) GetNodeByName(ctx context.Context, networkID, name string) (*models.Node, error) {
	var node models.Node
	var virtualIP string
	var labelsJSON, nodeInfoJSON []byte
	var lastSeen sql.NullTime
	
	err := s.db.QueryRowContext(ctx, `
		SELECT id, network_id, name, virtual_ip, public_key, labels, status, last_seen, node_info, expires_at, created_at
		FROM nodes WHERE network_id = $1 AND name = $2
	`, networkID, name).Scan(&node.ID, &node.NetworkID, &node.Name, &virtualIP, &node.PublicKey,
		&labelsJSON, &node.Status, &lastSeen, &nodeInfoJSON, &node.ExpiresAt, &node.CreatedAt)
	
	if err == sql.ErrNoRows {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	
	node.VirtualIP = net.ParseIP(virtualIP)
	if lastSeen.Valid {
		node.LastSeen = lastSeen.Time
	}
	json.Unmarshal(labelsJSON, &node.Labels)
	json.Unmarshal(nodeInfoJSON, &node.NodeInfo)
	
	return &node, nil
}

// ListNodes lists all nodes in a network
func (s *Store) ListNodes(ctx context.Context, networkID string) ([]*models.Node, error) {
	rows, err := s.db.QueryContext(ctx, `
		SELECT id, network_id, name, virtual_ip, public_key, labels, status, last_seen, node_info, expires_at, created_at
		FROM nodes WHERE network_id = $1 ORDER BY name
	`, networkID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	
	var nodes []*models.Node
	for rows.Next() {
		var node models.Node
		var virtualIP string
		var labelsJSON, nodeInfoJSON []byte
		var lastSeen sql.NullTime
		
		if err := rows.Scan(&node.ID, &node.NetworkID, &node.Name, &virtualIP, &node.PublicKey,
			&labelsJSON, &node.Status, &lastSeen, &nodeInfoJSON, &node.ExpiresAt, &node.CreatedAt); err != nil {
			return nil, err
		}
		
		node.VirtualIP = net.ParseIP(virtualIP)
		if lastSeen.Valid {
			node.LastSeen = lastSeen.Time
		}
		json.Unmarshal(labelsJSON, &node.Labels)
		json.Unmarshal(nodeInfoJSON, &node.NodeInfo)
		
		nodes = append(nodes, &node)
	}
	return nodes, rows.Err()
}

// UpdateNodeStatus updates node status and last seen time
func (s *Store) UpdateNodeStatus(ctx context.Context, id string, status models.NodeStatus) error {
	_, err := s.db.ExecContext(ctx, `
		UPDATE nodes SET status = $2, last_seen = $3 WHERE id = $1
	`, id, status, time.Now())
	return err
}

// UpdateNode updates all updatable fields of a node
func (s *Store) UpdateNode(ctx context.Context, node *models.Node) error {
	labelsJSON, _ := json.Marshal(node.Labels)
	nodeInfoJSON, _ := json.Marshal(node.NodeInfo)
	
	_, err := s.db.ExecContext(ctx, `
		UPDATE nodes 
		SET name = $2, labels = $3, status = $4, node_info = $5, expires_at = $6
		WHERE id = $1
	`, node.ID, node.Name, labelsJSON, node.Status, nodeInfoJSON, node.ExpiresAt)
	
	return err
}

// UpdateNodeEndpoints updates node endpoints
func (s *Store) UpdateNodeEndpoints(ctx context.Context, id string, endpoints []string) error {
	endpointsJSON, _ := json.Marshal(endpoints)
	_, err := s.db.ExecContext(ctx, `
		UPDATE nodes SET endpoints = $2 WHERE id = $1
	`, id, endpointsJSON)
	return err
}

// DeleteNode deletes a node
func (s *Store) DeleteNode(ctx context.Context, id string) error {
	_, err := s.db.ExecContext(ctx, `DELETE FROM nodes WHERE id = $1`, id)
	return err
}

// AllocateIP allocates the next available IP in the network
func (s *Store) AllocateIP(ctx context.Context, networkID string) (net.IP, error) {
	// Get network CIDR
	network, err := s.GetNetwork(ctx, networkID)
	if err != nil {
		return nil, err
	}
	if network == nil {
		return nil, fmt.Errorf("network not found")
	}
	
	_, ipNet, err := net.ParseCIDR(network.CIDR)
	if err != nil {
		return nil, fmt.Errorf("invalid network CIDR: %w", err)
	}
	
	// Get all allocated IPs
	rows, err := s.db.QueryContext(ctx, `
		SELECT virtual_ip FROM nodes WHERE network_id = $1
	`, networkID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	
	allocated := make(map[string]bool)
	for rows.Next() {
		var ip string
		if err := rows.Scan(&ip); err != nil {
			return nil, err
		}
		allocated[ip] = true
	}
	
	// Find next available IP (skip network and broadcast addresses)
	ip := ipNet.IP.Mask(ipNet.Mask)
	for i := 0; i < 3; i++ { // Skip first 3 IPs (network, gateway, reserved)
		ip = nextIP(ip)
	}
	
	for ipNet.Contains(ip) {
		if !allocated[ip.String()] {
			return ip, nil
		}
		ip = nextIP(ip)
	}
	
	return nil, fmt.Errorf("no available IPs in network")
}

// User operations
func (s *Store) GetUserByUsername(ctx context.Context, username string) (*models.User, error) {
	var user models.User
	err := s.db.QueryRowContext(ctx, `
		SELECT id, username, password_hash, created_at
		FROM users WHERE username = $1
	`, username).Scan(&user.ID, &user.Username, &user.PasswordHash, &user.CreatedAt)
	
	if err == sql.ErrNoRows {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	return &user, nil
}

// CreateUser creates a new user
func (s *Store) CreateUser(ctx context.Context, user *models.User) error {
	if user.ID == "" {
		user.ID = uuid.New().String()
	}
	user.CreatedAt = time.Now()
	
	_, err := s.db.ExecContext(ctx, `
		INSERT INTO users (id, username, password_hash, created_at)
		VALUES ($1, $2, $3, $4)
	`, user.ID, user.Username, user.PasswordHash, user.CreatedAt)
	
	return err
}

// UpdateUserPassword updates a user's password
func (s *Store) UpdateUserPassword(ctx context.Context, username, passwordHash string) error {
	result, err := s.db.ExecContext(ctx, `
		UPDATE users SET password_hash = $2 WHERE username = $1
	`, username, passwordHash)
	if err != nil {
		return err
	}
	
	rows, err := result.RowsAffected()
	if err != nil {
		return err
	}
	if rows == 0 {
		return sql.ErrNoRows
	}
	
	return nil
}

// ListUsers lists all users
func (s *Store) ListUsers(ctx context.Context) ([]*models.User, error) {
	rows, err := s.db.QueryContext(ctx, `
		SELECT id, username, created_at FROM users ORDER BY username
	`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	
	var users []*models.User
	for rows.Next() {
		var user models.User
		if err := rows.Scan(&user.ID, &user.Username, &user.CreatedAt); err != nil {
			return nil, err
		}
		users = append(users, &user)
	}
	return users, rows.Err()
}

// DeleteUser deletes a user
func (s *Store) DeleteUser(ctx context.Context, id string) error {
	_, err := s.db.ExecContext(ctx, `DELETE FROM users WHERE id = $1`, id)
	return err
}

// VPN Firewall Rule operations

// ListVPNFirewallRules lists all VPN firewall rules with joined network/node names
func (s *Store) ListVPNFirewallRules(ctx context.Context) ([]*models.VPNFirewallRule, error) {
	rows, err := s.db.QueryContext(ctx, `
		SELECT 
			fr.id, fr.name, fr.description,
			fr.source_type, fr.source_network_id, fr.source_node_id, fr.source_ip,
			fr.dest_type, fr.dest_network_id, fr.dest_node_id, fr.dest_ip,
			fr.protocol, fr.port, fr.action,
			fr.priority, fr.enabled, fr.created_at, fr.updated_at,
			sn.name as source_network_name,
			snode.name as source_node_name,
			dn.name as dest_network_name,
			dnode.name as dest_node_name
		FROM firewall_rules fr
		LEFT JOIN networks sn ON fr.source_network_id = sn.id
		LEFT JOIN nodes snode ON fr.source_node_id = snode.id
		LEFT JOIN networks dn ON fr.dest_network_id = dn.id
		LEFT JOIN nodes dnode ON fr.dest_node_id = dnode.id
		ORDER BY fr.priority ASC, fr.created_at ASC
	`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	
	var rules []*models.VPNFirewallRule
	for rows.Next() {
		var rule models.VPNFirewallRule
		var description, sourceIP, destIP, port sql.NullString
		var sourceNetworkID, sourceNodeID, destNetworkID, destNodeID sql.NullString
		var sourceNetworkName, sourceNodeName, destNetworkName, destNodeName sql.NullString
		
		if err := rows.Scan(
			&rule.ID, &rule.Name, &description,
			&rule.SourceType, &sourceNetworkID, &sourceNodeID, &sourceIP,
			&rule.DestType, &destNetworkID, &destNodeID, &destIP,
			&rule.Protocol, &port, &rule.Action,
			&rule.Priority, &rule.Enabled, &rule.CreatedAt, &rule.UpdatedAt,
			&sourceNetworkName, &sourceNodeName, &destNetworkName, &destNodeName,
		); err != nil {
			return nil, err
		}
		
		rule.Description = description.String
		rule.SourceIP = sourceIP.String
		rule.DestIP = destIP.String
		rule.Port = port.String
		
		if sourceNetworkID.Valid {
			rule.SourceNetworkID = &sourceNetworkID.String
		}
		if sourceNodeID.Valid {
			rule.SourceNodeID = &sourceNodeID.String
		}
		if destNetworkID.Valid {
			rule.DestNetworkID = &destNetworkID.String
		}
		if destNodeID.Valid {
			rule.DestNodeID = &destNodeID.String
		}
		
		rule.SourceNetworkName = sourceNetworkName.String
		rule.SourceNodeName = sourceNodeName.String
		rule.DestNetworkName = destNetworkName.String
		rule.DestNodeName = destNodeName.String
		
		rules = append(rules, &rule)
	}
	return rules, rows.Err()
}

// GetVPNFirewallRule retrieves a VPN firewall rule by ID
func (s *Store) GetVPNFirewallRule(ctx context.Context, id string) (*models.VPNFirewallRule, error) {
	var rule models.VPNFirewallRule
	var description, sourceIP, destIP, port sql.NullString
	var sourceNetworkID, sourceNodeID, destNetworkID, destNodeID sql.NullString
	var sourceNetworkName, sourceNodeName, destNetworkName, destNodeName sql.NullString
	
	err := s.db.QueryRowContext(ctx, `
		SELECT 
			fr.id, fr.name, fr.description,
			fr.source_type, fr.source_network_id, fr.source_node_id, fr.source_ip,
			fr.dest_type, fr.dest_network_id, fr.dest_node_id, fr.dest_ip,
			fr.protocol, fr.port, fr.action,
			fr.priority, fr.enabled, fr.created_at, fr.updated_at,
			sn.name as source_network_name,
			snode.name as source_node_name,
			dn.name as dest_network_name,
			dnode.name as dest_node_name
		FROM firewall_rules fr
		LEFT JOIN networks sn ON fr.source_network_id = sn.id
		LEFT JOIN nodes snode ON fr.source_node_id = snode.id
		LEFT JOIN networks dn ON fr.dest_network_id = dn.id
		LEFT JOIN nodes dnode ON fr.dest_node_id = dnode.id
		WHERE fr.id = $1
	`, id).Scan(
		&rule.ID, &rule.Name, &description,
		&rule.SourceType, &sourceNetworkID, &sourceNodeID, &sourceIP,
		&rule.DestType, &destNetworkID, &destNodeID, &destIP,
		&rule.Protocol, &port, &rule.Action,
		&rule.Priority, &rule.Enabled, &rule.CreatedAt, &rule.UpdatedAt,
		&sourceNetworkName, &sourceNodeName, &destNetworkName, &destNodeName,
	)
	
	if err == sql.ErrNoRows {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	
	rule.Description = description.String
	rule.SourceIP = sourceIP.String
	rule.DestIP = destIP.String
	rule.Port = port.String
	
	if sourceNetworkID.Valid {
		rule.SourceNetworkID = &sourceNetworkID.String
	}
	if sourceNodeID.Valid {
		rule.SourceNodeID = &sourceNodeID.String
	}
	if destNetworkID.Valid {
		rule.DestNetworkID = &destNetworkID.String
	}
	if destNodeID.Valid {
		rule.DestNodeID = &destNodeID.String
	}
	
	rule.SourceNetworkName = sourceNetworkName.String
	rule.SourceNodeName = sourceNodeName.String
	rule.DestNetworkName = destNetworkName.String
	rule.DestNodeName = destNodeName.String
	
	return &rule, nil
}

// CreateVPNFirewallRule creates a new VPN firewall rule
func (s *Store) CreateVPNFirewallRule(ctx context.Context, rule *models.VPNFirewallRule) error {
	if rule.ID == "" {
		rule.ID = uuid.New().String()
	}
	rule.CreatedAt = time.Now()
	rule.UpdatedAt = time.Now()
	
	_, err := s.db.ExecContext(ctx, `
		INSERT INTO firewall_rules (
			id, name, description,
			source_type, source_network_id, source_node_id, source_ip,
			dest_type, dest_network_id, dest_node_id, dest_ip,
			protocol, port, action,
			priority, enabled, created_at, updated_at
		) VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13, $14, $15, $16, $17, $18)
	`, rule.ID, rule.Name, nullString(rule.Description),
		rule.SourceType, nullStringPtr(rule.SourceNetworkID), nullStringPtr(rule.SourceNodeID), nullString(rule.SourceIP),
		rule.DestType, nullStringPtr(rule.DestNetworkID), nullStringPtr(rule.DestNodeID), nullString(rule.DestIP),
		rule.Protocol, nullString(rule.Port), rule.Action,
		rule.Priority, rule.Enabled, rule.CreatedAt, rule.UpdatedAt)
	
	return err
}

// UpdateVPNFirewallRule updates an existing VPN firewall rule
func (s *Store) UpdateVPNFirewallRule(ctx context.Context, rule *models.VPNFirewallRule) error {
	rule.UpdatedAt = time.Now()
	
	result, err := s.db.ExecContext(ctx, `
		UPDATE firewall_rules SET
			name = $2, description = $3,
			source_type = $4, source_network_id = $5, source_node_id = $6, source_ip = $7,
			dest_type = $8, dest_network_id = $9, dest_node_id = $10, dest_ip = $11,
			protocol = $12, port = $13, action = $14,
			priority = $15, enabled = $16, updated_at = $17
		WHERE id = $1
	`, rule.ID, rule.Name, nullString(rule.Description),
		rule.SourceType, nullStringPtr(rule.SourceNetworkID), nullStringPtr(rule.SourceNodeID), nullString(rule.SourceIP),
		rule.DestType, nullStringPtr(rule.DestNetworkID), nullStringPtr(rule.DestNodeID), nullString(rule.DestIP),
		rule.Protocol, nullString(rule.Port), rule.Action,
		rule.Priority, rule.Enabled, rule.UpdatedAt)
	
	if err != nil {
		return err
	}
	
	rows, err := result.RowsAffected()
	if err != nil {
		return err
	}
	if rows == 0 {
		return sql.ErrNoRows
	}
	
	return nil
}

// DeleteVPNFirewallRule deletes a VPN firewall rule
func (s *Store) DeleteVPNFirewallRule(ctx context.Context, id string) error {
	result, err := s.db.ExecContext(ctx, `DELETE FROM firewall_rules WHERE id = $1`, id)
	if err != nil {
		return err
	}
	
	rows, err := result.RowsAffected()
	if err != nil {
		return err
	}
	if rows == 0 {
		return sql.ErrNoRows
	}
	
	return nil
}

// CreateFirewallAuditLog creates an audit log entry for firewall changes
func (s *Store) CreateFirewallAuditLog(ctx context.Context, action string, details map[string]interface{}, userIP string) error {
	id := uuid.New().String()
	detailsJSON, _ := json.Marshal(details)
	
	_, err := s.db.ExecContext(ctx, `
		INSERT INTO firewall_audit_log (id, action, details, user_ip, created_at)
		VALUES ($1, $2, $3, $4, $5)
	`, id, action, detailsJSON, userIP, time.Now())
	
	return err
}

// Helper functions for nullable strings
func nullString(s string) sql.NullString {
	if s == "" {
		return sql.NullString{}
	}
	return sql.NullString{String: s, Valid: true}
}

func nullStringPtr(s *string) sql.NullString {
	if s == nil || *s == "" {
		return sql.NullString{}
	}
	return sql.NullString{String: *s, Valid: true}
}

// Helper functions

func nextIP(ip net.IP) net.IP {
	next := make(net.IP, len(ip))
	copy(next, ip)
	
	for i := len(next) - 1; i >= 0; i-- {
		next[i]++
		if next[i] != 0 {
			break
		}
	}
	return next
}
