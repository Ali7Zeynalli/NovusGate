package wireguard

import (
	"fmt"
	"os"
	"os/exec"
	"strings"
)

// Manager controls the WireGuard interface
type Manager struct {
	InterfaceName string
	ConfigPath    string
}

// NewManager creates a new WireGuard manager
func NewManager(interfaceName string) *Manager {
	return &Manager{
		InterfaceName: interfaceName,
		ConfigPath:    fmt.Sprintf("/etc/wireguard/%s.conf", interfaceName),
	}
}

// Init verifies wireguard tools are available
func (m *Manager) Init() error {
	_, err := exec.LookPath("wg")
	if err != nil {
		return fmt.Errorf("wg command not found")
	}
	return nil
}

// SetupInterface writes the config and brings up the interface
func (m *Manager) SetupInterface(configContent string) error {
	// Write config file
	err := os.WriteFile(m.ConfigPath, []byte(configContent), 0600)
	if err != nil {
		return fmt.Errorf("failed to write config: %w", err)
	}

	// Check if interface exists
	if m.isInterfaceUp() {
		// Sync config (restart)
		// Usually `wg-quick strip wg0 | wg syncconf wg0 /dev/stdin` is better but for MVP we restart
		m.Down()
	}

	return m.Up()
}

// Up brings the interface up using wg-quick
func (m *Manager) Up() error {
	cmd := exec.Command("wg-quick", "up", m.InterfaceName)
	output, err := cmd.CombinedOutput()
	if err != nil {
		return fmt.Errorf("wg-quick up failed: %s: %w", string(output), err)
	}
	return nil
}

// Down brings the interface down
func (m *Manager) Down() error {
	cmd := exec.Command("wg-quick", "down", m.InterfaceName)
	// Ignore error if down fails (maybe already down)
	_ = cmd.Run()
	return nil
}

// CreateServerConfig generates and writes the server configuration (generates new key)
func (m *Manager) CreateServerConfig(addressCIDR string, port int, peers []string) error {
	// 1. Generate Private Key
	privKey, err := m.generatePrivateKey()
	if err != nil {
		return fmt.Errorf("failed to generate private key: %w", err)
	}

	// 2. Generate Config Content
	gen := NewConfigGenerator()
	configContent := gen.GenerateServerConfig(privKey, port, addressCIDR)

	// 3. Write and Setup
	return m.SetupInterface(configContent)
}

// CreateServerConfigWithKey uses an existing private key to create the server config
func (m *Manager) CreateServerConfigWithKey(privateKey string, addressCIDR string, port int) error {
	// Generate Config Content using provided key
	gen := NewConfigGenerator()
	configContent := gen.GenerateServerConfig(privateKey, port, addressCIDR)

	// Write and Setup
	return m.SetupInterface(configContent)
}

func (m *Manager) generatePrivateKey() (string, error) {
	cmd := exec.Command("wg", "genkey")
	output, err := cmd.Output()
	if err != nil {
		return "", err
	}
	return strings.TrimSpace(string(output)), nil
}

// AddPeer adds a peer to the running interface
func (m *Manager) AddPeer(publicKey, allowedIPs string) error {
	// wg set wg0 peer <key> allowed-ips <ips>
	cmd := exec.Command("wg", "set", m.InterfaceName, "peer", publicKey, "allowed-ips", allowedIPs)
	output, err := cmd.CombinedOutput()
	if err != nil {
		return fmt.Errorf("failed to add peer: %s: %w", string(output), err)
	}
	return nil
}

// UpdatePeerAllowedIPs updates the allowed-ips for an existing peer
func (m *Manager) UpdatePeerAllowedIPs(publicKey, allowedIPs string) error {
	// wg set wg0 peer <key> allowed-ips <ips>
	// This command updates the peer if it exists
	cmd := exec.Command("wg", "set", m.InterfaceName, "peer", publicKey, "allowed-ips", allowedIPs)
	output, err := cmd.CombinedOutput()
	if err != nil {
		return fmt.Errorf("failed to update peer allowed-ips: %s: %w", string(output), err)
	}
	return nil
}

// RemovePeer removes a peer from the running interface
func (m *Manager) RemovePeer(publicKey string) error {
	// wg set wg0 peer <key> remove
	cmd := exec.Command("wg", "set", m.InterfaceName, "peer", publicKey, "remove")
	output, err := cmd.CombinedOutput()
	if err != nil {
		return fmt.Errorf("failed to remove peer: %s: %w", string(output), err)
	}
	return nil
}

func (m *Manager) isInterfaceUp() bool {
	// Simple check using ip link
	cmd := exec.Command("ip", "link", "show", m.InterfaceName)
	return cmd.Run() == nil
}

// GetPublicKey retrieves the server's public key by deriving it from the private key in the config
// If config doesn't exist, it generates and saves new keys
func (m *Manager) GetPublicKey() (string, error) {
	// 1. Try to read config to find PrivateKey
	content, err := os.ReadFile(m.ConfigPath)
	if err != nil {
		// Config doesn't exist - generate keys and create minimal config
		fmt.Printf("[INFO] Config file not found, generating new server keys...\n")
		privateKey, err := m.generatePrivateKey()
		if err != nil {
			return "", fmt.Errorf("failed to generate private key: %w", err)
		}
		
		// Create a minimal config with the generated key
		// Use 51820 as fallback port if not specified, but this path is usually for recovery
		configContent := fmt.Sprintf("[Interface]\nPrivateKey = %s\nAddress = 10.99.0.1/24\nListenPort = 51820\n", privateKey)
		
		// Ensure directory exists
		configDir := "/etc/wireguard"
		if err := os.MkdirAll(configDir, 0700); err != nil {
			return "", fmt.Errorf("failed to create config directory: %w", err)
		}
		
		if err := os.WriteFile(m.ConfigPath, []byte(configContent), 0600); err != nil {
			return "", fmt.Errorf("failed to write config: %w", err)
		}
		
		// Now derive public key from the new private key
		cmd := exec.Command("wg", "pubkey")
		cmd.Stdin = strings.NewReader(privateKey)
		output, err := cmd.Output()
		if err != nil {
			return "", fmt.Errorf("failed to derive public key: %w", err)
		}
		return strings.TrimSpace(string(output)), nil
	}
	
	// 2. Parse existing config for PrivateKey
	lines := strings.Split(string(content), "\n")
	var privateKey string
	for _, line := range lines {
		trimmed := strings.TrimSpace(line)
		if strings.HasPrefix(trimmed, "PrivateKey") {
			parts := strings.Split(trimmed, "=")
			if len(parts) >= 2 {
				privateKey = strings.TrimSpace(parts[1])
				break
			}
		}
	}

	if privateKey == "" {
		return "", fmt.Errorf("private key not found in config")
	}

	// 3. Derive Public Key
	cmd := exec.Command("wg", "pubkey")
	cmd.Stdin = strings.NewReader(privateKey)
	output, err := cmd.Output()
	if err != nil {
		if exitErr, ok := err.(*exec.ExitError); ok {
			return "", fmt.Errorf("wg pubkey failed: %v, stderr: %s", err, string(exitErr.Stderr))
		}
		return "", fmt.Errorf("failed to derive public key: %w", err)
	}
	
	return strings.TrimSpace(string(output)), nil
}

// PeerStatus contains real-time information about a WireGuard peer
type PeerStatus struct {
	PublicKey           string
	Endpoint            string
	AllowedIPs          string 
	LatestHandshakeTime int64
	TransferRx          int64
	TransferTx          int64
}

// GetPeers returns the status of all peers on the interface
func (m *Manager) GetPeers() (map[string]PeerStatus, error) {
	cmd := exec.Command("wg", "show", m.InterfaceName, "dump")
	output, err := cmd.Output()
	if err != nil {
		return nil, fmt.Errorf("failed to dump wg status: %w", err)
	}

	peers := make(map[string]PeerStatus)
	lines := strings.Split(string(output), "\n")
	
	for _, line := range lines {
		fields := strings.Fields(line)
		// Skip interface config line (usually the first one) or peers with too few fields
		if len(fields) < 8 {
			continue
		}

		status := PeerStatus{
			PublicKey:  fields[0],
			Endpoint:   fields[2],
			AllowedIPs: fields[3],
		}
		
		fmt.Sscanf(fields[4], "%d", &status.LatestHandshakeTime)
		fmt.Sscanf(fields[5], "%d", &status.TransferRx)
		fmt.Sscanf(fields[6], "%d", &status.TransferTx)

		peers[status.PublicKey] = status
	}

	return peers, nil
}


