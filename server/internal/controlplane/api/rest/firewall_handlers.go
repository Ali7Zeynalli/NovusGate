package rest

import (
	"context"
	"encoding/json"
	"fmt"
	"net"
	"net/http"
	"regexp"
	"strconv"
	"strings"

	"github.com/gorilla/mux"
	"github.com/novusgate/novusgate/internal/shared/models"
)

// FirewallRule represents a parsed iptables rule
type FirewallRule struct {
	Number      int    `json:"number"`
	Chain       string `json:"chain"`
	Target      string `json:"target"`      // ACCEPT, DROP, REJECT
	Protocol    string `json:"protocol"`    // tcp, udp, icmp, all
	Source      string `json:"source"`      // IP/CIDR or "anywhere"
	Destination string `json:"destination"` // IP/CIDR or "anywhere"
	Port        string `json:"port"`        // port number or range
	Interface   string `json:"interface"`   // wg0, eth0, etc.
	InInterface string `json:"in_interface,omitempty"`
	OutInterface string `json:"out_interface,omitempty"`
	Options     string `json:"options,omitempty"`
	Protected   bool   `json:"protected"`   // Cannot be deleted
}

// ChainInfo represents information about an iptables chain
type ChainInfo struct {
	Name   string         `json:"name"`
	Policy string         `json:"policy"` // ACCEPT or DROP
	Rules  []FirewallRule `json:"rules"`
}

// FirewallStatus represents the overall firewall status
type FirewallStatus struct {
	Chains      []ChainInfo `json:"chains"`
	TotalRules  int         `json:"total_rules"`
	BlockedIPs  int         `json:"blocked_ips"`
	OpenPorts   int         `json:"open_ports"`
}

// OpenPortRequest represents a request to open a port
type OpenPortRequest struct {
	Port     int    `json:"port"`
	Protocol string `json:"protocol"` // tcp, udp, both
	Source   string `json:"source"`   // Optional: restrict to IP/CIDR
}

// ClosePortRequest represents a request to close a port
type ClosePortRequest struct {
	Port     int    `json:"port"`
	Protocol string `json:"protocol"` // tcp, udp, both
	Force    bool   `json:"force"`    // Force close even if SSH port
}


// BlockIPRequest represents a request to block an IP
type BlockIPRequest struct {
	IP    string `json:"ip"`    // IP or CIDR
	Ports string `json:"ports"` // Optional: specific ports, empty = all
}

// AllowIPRequest represents a request to allow an IP
type AllowIPRequest struct {
	IP    string `json:"ip"`    // IP or CIDR
	Ports string `json:"ports"` // Optional: specific ports, empty = all
}

// DeleteRuleRequest represents a request to delete a rule
type DeleteRuleRequest struct {
	Chain      string `json:"chain"`
	LineNumber int    `json:"line_number"`
	Force      bool   `json:"force"` // Force delete even if protected
}

// ImportRulesRequest represents a request to import firewall rules
type ImportRulesRequest struct {
	Rules string `json:"rules"` // iptables-save format
}

// Protected ports that cannot be easily closed
var protectedPorts = map[int]string{
	22: "SSH",
}

// isProtectedRule checks if a rule is protected (SSH, WireGuard, Admin API)
func isProtectedRule(rule FirewallRule) bool {
	// Protect SSH rules
	if rule.Port == "22" && rule.Target == "ACCEPT" {
		return true
	}
	
	// Protect WireGuard ports (51820+)
	if rule.Port != "" {
		port, err := strconv.Atoi(rule.Port)
		if err == nil && port >= 51820 && port <= 51830 && rule.Target == "ACCEPT" {
			return true
		}
	}
	
	// Protect rules for wg+ interfaces (WireGuard)
	if strings.HasPrefix(rule.Interface, "wg") || strings.HasPrefix(rule.InInterface, "wg") {
		return true
	}
	
	return false
}


// parseIptablesOutput parses the output of iptables -L -n -v --line-numbers
func parseIptablesOutput(output string, chainName string) (*ChainInfo, error) {
	lines := strings.Split(output, "\n")
	chain := &ChainInfo{
		Name:   chainName,
		Policy: "ACCEPT",
		Rules:  []FirewallRule{},
	}
	
	// Parse chain header for policy
	// Format: "Chain INPUT (policy ACCEPT 0 packets, 0 bytes)"
	for _, line := range lines {
		if strings.HasPrefix(line, "Chain "+chainName) {
			if strings.Contains(line, "policy DROP") {
				chain.Policy = "DROP"
			} else if strings.Contains(line, "policy REJECT") {
				chain.Policy = "REJECT"
			}
			break
		}
	}
	
	// Parse rules
	// Format: "num   pkts bytes target     prot opt in     out     source               destination"
	// Example: "1     100  5000 ACCEPT     tcp  --  *      *       0.0.0.0/0            0.0.0.0/0            tcp dpt:22"
	inRules := false
	for _, line := range lines {
		line = strings.TrimSpace(line)
		
		// Skip empty lines
		if line == "" {
			continue
		}
		
		// Skip header line
		if strings.HasPrefix(line, "num") || strings.HasPrefix(line, "Chain") {
			if strings.HasPrefix(line, "Chain "+chainName) {
				inRules = true
			}
			continue
		}
		
		if !inRules {
			continue
		}
		
		// Stop if we hit another chain
		if strings.HasPrefix(line, "Chain ") {
			break
		}
		
		rule := parseRuleLine(line, chainName)
		if rule != nil {
			rule.Protected = isProtectedRule(*rule)
			chain.Rules = append(chain.Rules, *rule)
		}
	}
	
	return chain, nil
}


// parseRuleLine parses a single iptables rule line
func parseRuleLine(line string, chainName string) *FirewallRule {
	// Split by whitespace, but be careful with multiple spaces
	fields := strings.Fields(line)
	if len(fields) < 8 {
		return nil
	}
	
	// Parse line number
	lineNum, err := strconv.Atoi(fields[0])
	if err != nil {
		return nil
	}
	
	rule := &FirewallRule{
		Number: lineNum,
		Chain:  chainName,
	}
	
	// fields[1] = pkts, fields[2] = bytes (skip these)
	// fields[3] = target
	rule.Target = fields[3]
	
	// fields[4] = protocol
	rule.Protocol = fields[4]
	
	// fields[5] = opt (skip)
	
	// fields[6] = in interface
	if fields[6] != "*" {
		rule.InInterface = fields[6]
		rule.Interface = fields[6]
	}
	
	// fields[7] = out interface
	if fields[7] != "*" {
		rule.OutInterface = fields[7]
		if rule.Interface == "" {
			rule.Interface = fields[7]
		}
	}
	
	// fields[8] = source
	if len(fields) > 8 {
		rule.Source = fields[8]
		if rule.Source == "0.0.0.0/0" {
			rule.Source = "anywhere"
		}
	}
	
	// fields[9] = destination
	if len(fields) > 9 {
		rule.Destination = fields[9]
		if rule.Destination == "0.0.0.0/0" {
			rule.Destination = "anywhere"
		}
	}
	
	// Parse remaining fields for port info
	// Look for patterns like "tcp dpt:22" or "tcp dpts:8000:9000" or "multiport dports 80,443"
	remaining := strings.Join(fields[10:], " ")
	rule.Options = remaining
	
	// Extract port from options
	rule.Port = extractPort(remaining)
	
	return rule
}


// extractPort extracts port information from iptables options string
func extractPort(options string) string {
	// Match patterns like "dpt:22", "dpts:8000:9000", "dports 80,443"
	patterns := []string{
		`dpt:(\d+)`,           // Single port
		`dpts:(\d+:\d+)`,      // Port range
		`dports\s+(\S+)`,      // Multiple ports
		`spt:(\d+)`,           // Source port
		`spts:(\d+:\d+)`,      // Source port range
	}
	
	for _, pattern := range patterns {
		re := regexp.MustCompile(pattern)
		matches := re.FindStringSubmatch(options)
		if len(matches) > 1 {
			return matches[1]
		}
	}
	
	return ""
}

// handleFirewallGetRules returns all iptables rules grouped by chain
func (s *Server) handleFirewallGetRules(w http.ResponseWriter, r *http.Request) {
	// Get chain from query param, default to all
	chainFilter := r.URL.Query().Get("chain")
	
	chains := []string{"INPUT", "FORWARD", "OUTPUT"}
	if chainFilter != "" {
		chainFilter = strings.ToUpper(chainFilter)
		if chainFilter != "INPUT" && chainFilter != "FORWARD" && chainFilter != "OUTPUT" {
			errorResponse(w, http.StatusBadRequest, "invalid chain: must be INPUT, FORWARD, or OUTPUT")
			return
		}
		chains = []string{chainFilter}
	}
	
	result := FirewallStatus{
		Chains:     []ChainInfo{},
		TotalRules: 0,
		BlockedIPs: 0,
		OpenPorts:  0,
	}
	
	for _, chainName := range chains {
		// Execute iptables command via nsenter (for Docker compatibility)
		output, err := execHostCommand("iptables", "-L", chainName, "-n", "-v", "--line-numbers")
		if err != nil {
			errorResponse(w, http.StatusInternalServerError, fmt.Sprintf("failed to get %s chain: %v", chainName, err))
			return
		}
		
		chain, err := parseIptablesOutput(output, chainName)
		if err != nil {
			errorResponse(w, http.StatusInternalServerError, fmt.Sprintf("failed to parse %s chain: %v", chainName, err))
			return
		}
		
		result.Chains = append(result.Chains, *chain)
		result.TotalRules += len(chain.Rules)
		
		// Count blocked IPs and open ports
		for _, rule := range chain.Rules {
			if rule.Target == "DROP" || rule.Target == "REJECT" {
				if rule.Source != "anywhere" && rule.Source != "" {
					result.BlockedIPs++
				}
			}
			if rule.Target == "ACCEPT" && rule.Port != "" && chainName == "INPUT" {
				result.OpenPorts++
			}
		}
	}
	
	jsonResponse(w, http.StatusOK, result)
}


// handleFirewallOpenPort opens a port in the firewall
func (s *Server) handleFirewallOpenPort(w http.ResponseWriter, r *http.Request) {
	var req OpenPortRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		errorResponse(w, http.StatusBadRequest, "invalid request body")
		return
	}
	
	// Validate port
	if req.Port < 1 || req.Port > 65535 {
		errorResponse(w, http.StatusBadRequest, "invalid port number: must be between 1 and 65535")
		return
	}
	
	// Validate protocol
	if req.Protocol == "" {
		req.Protocol = "tcp"
	}
	req.Protocol = strings.ToLower(req.Protocol)
	if req.Protocol != "tcp" && req.Protocol != "udp" && req.Protocol != "both" {
		errorResponse(w, http.StatusBadRequest, "invalid protocol: must be tcp, udp, or both")
		return
	}
	
	// Validate source IP if provided
	if req.Source != "" {
		if net.ParseIP(req.Source) == nil {
			if _, _, err := net.ParseCIDR(req.Source); err != nil {
				errorResponse(w, http.StatusBadRequest, "invalid source IP/CIDR")
				return
			}
		}
	}
	
	protocols := []string{req.Protocol}
	if req.Protocol == "both" {
		protocols = []string{"tcp", "udp"}
	}
	
	for _, proto := range protocols {
		args := []string{"-A", "INPUT", "-p", proto, "--dport", strconv.Itoa(req.Port), "-j", "ACCEPT"}
		if req.Source != "" {
			args = []string{"-A", "INPUT", "-s", req.Source, "-p", proto, "--dport", strconv.Itoa(req.Port), "-j", "ACCEPT"}
		}
		
		_, err := execHostCommand("iptables", args...)
		if err != nil {
			errorResponse(w, http.StatusInternalServerError, fmt.Sprintf("failed to open port: %v", err))
			return
		}
	}
	
	// Save rules with netfilter-persistent
	execHostCommand("netfilter-persistent", "save")
	
	jsonResponse(w, http.StatusOK, map[string]interface{}{
		"status":   "success",
		"message":  fmt.Sprintf("Port %d/%s opened successfully", req.Port, req.Protocol),
		"port":     req.Port,
		"protocol": req.Protocol,
		"source":   req.Source,
	})
}


// handleFirewallClosePort closes a port in the firewall
func (s *Server) handleFirewallClosePort(w http.ResponseWriter, r *http.Request) {
	var req ClosePortRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		errorResponse(w, http.StatusBadRequest, "invalid request body")
		return
	}
	
	// Validate port
	if req.Port < 1 || req.Port > 65535 {
		errorResponse(w, http.StatusBadRequest, "invalid port number: must be between 1 and 65535")
		return
	}
	
	// Check if this is a protected port
	if portName, isProtected := protectedPorts[req.Port]; isProtected && !req.Force {
		errorResponse(w, http.StatusForbidden, fmt.Sprintf("port %d (%s) is protected. Set force=true to override", req.Port, portName))
		return
	}
	
	// Validate protocol
	if req.Protocol == "" {
		req.Protocol = "tcp"
	}
	req.Protocol = strings.ToLower(req.Protocol)
	if req.Protocol != "tcp" && req.Protocol != "udp" && req.Protocol != "both" {
		errorResponse(w, http.StatusBadRequest, "invalid protocol: must be tcp, udp, or both")
		return
	}
	
	protocols := []string{req.Protocol}
	if req.Protocol == "both" {
		protocols = []string{"tcp", "udp"}
	}
	
	deletedCount := 0
	for _, proto := range protocols {
		// Find and delete all ACCEPT rules for this port
		// We need to loop because there might be multiple rules
		for {
			// Get current rules
			output, err := execHostCommand("iptables", "-L", "INPUT", "-n", "-v", "--line-numbers")
			if err != nil {
				break
			}
			
			// Find rule number for this port
			lineNum := findRuleLineNumber(output, proto, req.Port, "ACCEPT")
			if lineNum == 0 {
				break
			}
			
			// Delete the rule
			_, err = execHostCommand("iptables", "-D", "INPUT", strconv.Itoa(lineNum))
			if err != nil {
				break
			}
			deletedCount++
		}
	}
	
	// Save rules with netfilter-persistent
	execHostCommand("netfilter-persistent", "save")
	
	jsonResponse(w, http.StatusOK, map[string]interface{}{
		"status":        "success",
		"message":       fmt.Sprintf("Port %d/%s closed successfully", req.Port, req.Protocol),
		"port":          req.Port,
		"protocol":      req.Protocol,
		"rules_deleted": deletedCount,
	})
}

// findRuleLineNumber finds the line number of a rule matching the criteria
func findRuleLineNumber(output string, protocol string, port int, target string) int {
	lines := strings.Split(output, "\n")
	portStr := strconv.Itoa(port)
	
	for _, line := range lines {
		fields := strings.Fields(line)
		if len(fields) < 4 {
			continue
		}
		
		// Check if this line matches our criteria
		lineNum, err := strconv.Atoi(fields[0])
		if err != nil {
			continue
		}
		
		// Check target
		if fields[3] != target {
			continue
		}
		
		// Check protocol
		if fields[4] != protocol {
			continue
		}
		
		// Check port in the options
		if strings.Contains(line, "dpt:"+portStr) || strings.Contains(line, "dpts:"+portStr) {
			return lineNum
		}
	}
	
	return 0
}


// handleFirewallBlockIP blocks an IP address
func (s *Server) handleFirewallBlockIP(w http.ResponseWriter, r *http.Request) {
	var req BlockIPRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		errorResponse(w, http.StatusBadRequest, "invalid request body")
		return
	}
	
	// Validate IP/CIDR
	if req.IP == "" {
		errorResponse(w, http.StatusBadRequest, "ip is required")
		return
	}
	
	if net.ParseIP(req.IP) == nil {
		if _, _, err := net.ParseCIDR(req.IP); err != nil {
			errorResponse(w, http.StatusBadRequest, "invalid IP address or CIDR")
			return
		}
	}
	
	// Build iptables command
	args := []string{"-I", "INPUT", "-s", req.IP}
	
	// Add port restriction if specified
	if req.Ports != "" {
		// Parse ports - could be single port, range, or comma-separated
		if strings.Contains(req.Ports, ",") {
			// Multiple ports - use multiport
			args = append(args, "-p", "tcp", "-m", "multiport", "--dports", req.Ports)
		} else if strings.Contains(req.Ports, ":") {
			// Port range
			args = append(args, "-p", "tcp", "--dport", req.Ports)
		} else {
			// Single port
			args = append(args, "-p", "tcp", "--dport", req.Ports)
		}
	}
	
	args = append(args, "-j", "DROP")
	
	_, err := execHostCommand("iptables", args...)
	if err != nil {
		errorResponse(w, http.StatusInternalServerError, fmt.Sprintf("failed to block IP: %v", err))
		return
	}
	
	// Save rules with netfilter-persistent
	execHostCommand("netfilter-persistent", "save")
	
	jsonResponse(w, http.StatusOK, map[string]interface{}{
		"status":  "success",
		"message": fmt.Sprintf("IP %s blocked successfully", req.IP),
		"ip":      req.IP,
		"ports":   req.Ports,
	})
}

// handleFirewallAllowIP allows an IP address
func (s *Server) handleFirewallAllowIP(w http.ResponseWriter, r *http.Request) {
	var req AllowIPRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		errorResponse(w, http.StatusBadRequest, "invalid request body")
		return
	}
	
	// Validate IP/CIDR
	if req.IP == "" {
		errorResponse(w, http.StatusBadRequest, "ip is required")
		return
	}
	
	if net.ParseIP(req.IP) == nil {
		if _, _, err := net.ParseCIDR(req.IP); err != nil {
			errorResponse(w, http.StatusBadRequest, "invalid IP address or CIDR")
			return
		}
	}
	
	// Build iptables command
	args := []string{"-I", "INPUT", "-s", req.IP}
	
	// Add port restriction if specified
	if req.Ports != "" {
		if strings.Contains(req.Ports, ",") {
			args = append(args, "-p", "tcp", "-m", "multiport", "--dports", req.Ports)
		} else if strings.Contains(req.Ports, ":") {
			args = append(args, "-p", "tcp", "--dport", req.Ports)
		} else {
			args = append(args, "-p", "tcp", "--dport", req.Ports)
		}
	}
	
	args = append(args, "-j", "ACCEPT")
	
	_, err := execHostCommand("iptables", args...)
	if err != nil {
		errorResponse(w, http.StatusInternalServerError, fmt.Sprintf("failed to allow IP: %v", err))
		return
	}
	
	// Save rules with netfilter-persistent
	execHostCommand("netfilter-persistent", "save")
	
	jsonResponse(w, http.StatusOK, map[string]interface{}{
		"status":  "success",
		"message": fmt.Sprintf("IP %s allowed successfully", req.IP),
		"ip":      req.IP,
		"ports":   req.Ports,
	})
}


// handleFirewallDeleteRule deletes a firewall rule by chain and line number
func (s *Server) handleFirewallDeleteRule(w http.ResponseWriter, r *http.Request) {
	var req DeleteRuleRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		errorResponse(w, http.StatusBadRequest, "invalid request body")
		return
	}
	
	// Validate chain
	req.Chain = strings.ToUpper(req.Chain)
	if req.Chain != "INPUT" && req.Chain != "FORWARD" && req.Chain != "OUTPUT" {
		errorResponse(w, http.StatusBadRequest, "invalid chain: must be INPUT, FORWARD, or OUTPUT")
		return
	}
	
	// Validate line number
	if req.LineNumber < 1 {
		errorResponse(w, http.StatusBadRequest, "invalid line number: must be >= 1")
		return
	}
	
	// Get current rules to check if protected
	output, err := execHostCommand("iptables", "-L", req.Chain, "-n", "-v", "--line-numbers")
	if err != nil {
		errorResponse(w, http.StatusInternalServerError, fmt.Sprintf("failed to get rules: %v", err))
		return
	}
	
	// Parse and find the rule
	chain, err := parseIptablesOutput(output, req.Chain)
	if err != nil {
		errorResponse(w, http.StatusInternalServerError, fmt.Sprintf("failed to parse rules: %v", err))
		return
	}
	
	// Find the rule by line number
	var targetRule *FirewallRule
	for _, rule := range chain.Rules {
		if rule.Number == req.LineNumber {
			targetRule = &rule
			break
		}
	}
	
	if targetRule == nil {
		errorResponse(w, http.StatusNotFound, fmt.Sprintf("rule %d not found in chain %s", req.LineNumber, req.Chain))
		return
	}
	
	// Check if protected
	if targetRule.Protected && !req.Force {
		errorResponse(w, http.StatusForbidden, fmt.Sprintf("rule %d is protected (SSH/WireGuard/Admin). Set force=true to override", req.LineNumber))
		return
	}
	
	// Delete the rule
	_, err = execHostCommand("iptables", "-D", req.Chain, strconv.Itoa(req.LineNumber))
	if err != nil {
		errorResponse(w, http.StatusInternalServerError, fmt.Sprintf("failed to delete rule: %v", err))
		return
	}
	
	// Save rules with netfilter-persistent
	execHostCommand("netfilter-persistent", "save")
	
	jsonResponse(w, http.StatusOK, map[string]interface{}{
		"status":      "success",
		"message":     fmt.Sprintf("Rule %d deleted from chain %s", req.LineNumber, req.Chain),
		"chain":       req.Chain,
		"line_number": req.LineNumber,
		"deleted_rule": targetRule,
	})
}


// handleFirewallExport exports all iptables rules in iptables-save format
func (s *Server) handleFirewallExport(w http.ResponseWriter, r *http.Request) {
	output, err := execHostCommand("iptables-save")
	if err != nil {
		errorResponse(w, http.StatusInternalServerError, fmt.Sprintf("failed to export rules: %v", err))
		return
	}
	
	// Set headers for file download
	w.Header().Set("Content-Type", "text/plain")
	w.Header().Set("Content-Disposition", "attachment; filename=\"iptables-rules.txt\"")
	w.Write([]byte(output))
}

// handleFirewallImport imports iptables rules from iptables-restore format
func (s *Server) handleFirewallImport(w http.ResponseWriter, r *http.Request) {
	var req ImportRulesRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		errorResponse(w, http.StatusBadRequest, "invalid request body")
		return
	}
	
	if req.Rules == "" {
		errorResponse(w, http.StatusBadRequest, "rules content is required")
		return
	}
	
	// Validate the rules format
	if !strings.Contains(req.Rules, "*filter") && !strings.Contains(req.Rules, "*nat") && !strings.Contains(req.Rules, "*mangle") {
		errorResponse(w, http.StatusBadRequest, "invalid iptables-save format: missing table declaration")
		return
	}
	
	// Create a temporary file for the rules
	tmpFile := "/tmp/iptables-import.txt"
	err := writeHostFile(tmpFile, req.Rules)
	if err != nil {
		errorResponse(w, http.StatusInternalServerError, fmt.Sprintf("failed to write temporary file: %v", err))
		return
	}
	
	// Apply the rules using iptables-restore
	_, err = execHostCommand("iptables-restore", tmpFile)
	if err != nil {
		errorResponse(w, http.StatusInternalServerError, fmt.Sprintf("failed to import rules: %v", err))
		return
	}
	
	// Save rules with netfilter-persistent
	execHostCommand("netfilter-persistent", "save")
	
	// Clean up temp file
	execHostCommand("rm", "-f", tmpFile)
	
	jsonResponse(w, http.StatusOK, map[string]interface{}{
		"status":  "success",
		"message": "Firewall rules imported successfully",
	})
}

// writeHostFile writes content to a file on the host system
func writeHostFile(path string, content string) error {
	// Use nsenter to write file on host
	cmd := fmt.Sprintf("echo '%s' > %s", strings.ReplaceAll(content, "'", "'\\''"), path)
	_, err := execHostCommand("sh", "-c", cmd)
	return err
}


// handleFirewallReset resets firewall to default NovusGate configuration
func (s *Server) handleFirewallReset(w http.ResponseWriter, r *http.Request) {
	// Default NovusGate firewall rules
	defaultRules := `*filter
:INPUT DROP [0:0]
:FORWARD DROP [0:0]
:OUTPUT ACCEPT [0:0]

# Allow loopback
-A INPUT -i lo -j ACCEPT
-A OUTPUT -o lo -j ACCEPT

# Allow established connections
-A INPUT -m state --state ESTABLISHED,RELATED -j ACCEPT
-A FORWARD -m state --state ESTABLISHED,RELATED -j ACCEPT

# Allow SSH
-A INPUT -p tcp --dport 22 -j ACCEPT

# Allow WireGuard (51820-51830)
-A INPUT -p udp --dport 51820:51830 -j ACCEPT

# Allow HTTP/HTTPS for web panel
-A INPUT -p tcp --dport 80 -j ACCEPT
-A INPUT -p tcp --dport 443 -j ACCEPT

# Allow API port
-A INPUT -p tcp --dport 8080 -j ACCEPT

# Allow ICMP (ping)
-A INPUT -p icmp -j ACCEPT

# Allow all traffic from WireGuard interfaces
-A INPUT -i wg+ -j ACCEPT
-A FORWARD -i wg+ -j ACCEPT
-A FORWARD -o wg+ -j ACCEPT

COMMIT
`
	
	// Create a temporary file for the rules
	tmpFile := "/tmp/iptables-default.txt"
	err := writeHostFile(tmpFile, defaultRules)
	if err != nil {
		errorResponse(w, http.StatusInternalServerError, fmt.Sprintf("failed to write temporary file: %v", err))
		return
	}
	
	// Apply the rules using iptables-restore
	_, err = execHostCommand("iptables-restore", tmpFile)
	if err != nil {
		errorResponse(w, http.StatusInternalServerError, fmt.Sprintf("failed to reset firewall: %v", err))
		return
	}
	
	// Save rules with netfilter-persistent
	execHostCommand("netfilter-persistent", "save")
	
	// Clean up temp file
	execHostCommand("rm", "-f", tmpFile)
	
	jsonResponse(w, http.StatusOK, map[string]interface{}{
		"status":  "success",
		"message": "Firewall reset to default NovusGate configuration",
	})
}


// =============================================================================
// VPN Firewall Handlers
// =============================================================================

// VPNFirewallRuleRequest represents a request to create/update a VPN firewall rule
type VPNFirewallRuleRequest struct {
	Name            string  `json:"name"`
	Description     string  `json:"description,omitempty"`
	SourceType      string  `json:"source_type"`       // any, network, node, custom
	SourceNetworkID *string `json:"source_network_id,omitempty"`
	SourceNodeID    *string `json:"source_node_id,omitempty"`
	SourceIP        string  `json:"source_ip,omitempty"`
	DestType        string  `json:"dest_type"`         // any, network, node, custom
	DestNetworkID   *string `json:"dest_network_id,omitempty"`
	DestNodeID      *string `json:"dest_node_id,omitempty"`
	DestIP          string  `json:"dest_ip,omitempty"`
	Protocol        string  `json:"protocol"`          // tcp, udp, icmp, all
	Port            string  `json:"port,omitempty"`
	Action          string  `json:"action"`            // accept, drop, reject
	Priority        int     `json:"priority"`
	Enabled         bool    `json:"enabled"`
}

// validateVPNFirewallRule validates a VPN firewall rule request
func validateVPNFirewallRule(req *VPNFirewallRuleRequest) error {
	if req.Name == "" {
		return fmt.Errorf("name is required")
	}
	
	// Validate source type
	validTypes := map[string]bool{"any": true, "network": true, "node": true, "custom": true}
	if !validTypes[req.SourceType] {
		return fmt.Errorf("invalid source_type: must be any, network, node, or custom")
	}
	
	// Validate destination type
	if !validTypes[req.DestType] {
		return fmt.Errorf("invalid dest_type: must be any, network, node, or custom")
	}
	
	// Validate source references based on type
	switch req.SourceType {
	case "network":
		if req.SourceNetworkID == nil || *req.SourceNetworkID == "" {
			return fmt.Errorf("source_network_id is required when source_type is network")
		}
	case "node":
		if req.SourceNodeID == nil || *req.SourceNodeID == "" {
			return fmt.Errorf("source_node_id is required when source_type is node")
		}
	case "custom":
		if req.SourceIP == "" {
			return fmt.Errorf("source_ip is required when source_type is custom")
		}
		// Validate IP/CIDR format
		if net.ParseIP(req.SourceIP) == nil {
			if _, _, err := net.ParseCIDR(req.SourceIP); err != nil {
				return fmt.Errorf("invalid source_ip: must be valid IP or CIDR")
			}
		}
	}
	
	// Validate destination references based on type
	switch req.DestType {
	case "network":
		if req.DestNetworkID == nil || *req.DestNetworkID == "" {
			return fmt.Errorf("dest_network_id is required when dest_type is network")
		}
	case "node":
		if req.DestNodeID == nil || *req.DestNodeID == "" {
			return fmt.Errorf("dest_node_id is required when dest_type is node")
		}
	case "custom":
		if req.DestIP == "" {
			return fmt.Errorf("dest_ip is required when dest_type is custom")
		}
		// Validate IP/CIDR format
		if net.ParseIP(req.DestIP) == nil {
			if _, _, err := net.ParseCIDR(req.DestIP); err != nil {
				return fmt.Errorf("invalid dest_ip: must be valid IP or CIDR")
			}
		}
	}
	
	// Validate protocol
	validProtocols := map[string]bool{"tcp": true, "udp": true, "icmp": true, "all": true}
	if req.Protocol == "" {
		req.Protocol = "all"
	}
	req.Protocol = strings.ToLower(req.Protocol)
	if !validProtocols[req.Protocol] {
		return fmt.Errorf("invalid protocol: must be tcp, udp, icmp, or all")
	}
	
	// Validate action
	validActions := map[string]bool{"accept": true, "drop": true, "reject": true}
	req.Action = strings.ToLower(req.Action)
	if !validActions[req.Action] {
		return fmt.Errorf("invalid action: must be accept, drop, or reject")
	}
	
	// Validate port (only for tcp/udp)
	if req.Port != "" && req.Protocol != "tcp" && req.Protocol != "udp" {
		return fmt.Errorf("port can only be specified for tcp or udp protocols")
	}
	
	return nil
}

// handleVPNFirewallGetRules returns all VPN firewall rules from database
func (s *Server) handleVPNFirewallGetRules(w http.ResponseWriter, r *http.Request) {
	rules, err := s.store.ListVPNFirewallRules(r.Context())
	if err != nil {
		errorResponse(w, http.StatusInternalServerError, fmt.Sprintf("failed to get VPN firewall rules: %v", err))
		return
	}
	
	if rules == nil {
		rules = []*models.VPNFirewallRule{}
	}
	
	jsonResponse(w, http.StatusOK, rules)
}

// handleVPNFirewallCreateRule creates a new VPN firewall rule
func (s *Server) handleVPNFirewallCreateRule(w http.ResponseWriter, r *http.Request) {
	var req VPNFirewallRuleRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		errorResponse(w, http.StatusBadRequest, "invalid request body")
		return
	}
	
	// Validate the request
	if err := validateVPNFirewallRule(&req); err != nil {
		errorResponse(w, http.StatusBadRequest, err.Error())
		return
	}
	
	// Create the rule model
	rule := &models.VPNFirewallRule{
		Name:            req.Name,
		Description:     req.Description,
		SourceType:      req.SourceType,
		SourceNetworkID: req.SourceNetworkID,
		SourceNodeID:    req.SourceNodeID,
		SourceIP:        req.SourceIP,
		DestType:        req.DestType,
		DestNetworkID:   req.DestNetworkID,
		DestNodeID:      req.DestNodeID,
		DestIP:          req.DestIP,
		Protocol:        req.Protocol,
		Port:            req.Port,
		Action:          req.Action,
		Priority:        req.Priority,
		Enabled:         req.Enabled,
	}
	
	// Save to database
	if err := s.store.CreateVPNFirewallRule(r.Context(), rule); err != nil {
		errorResponse(w, http.StatusInternalServerError, fmt.Sprintf("failed to create VPN firewall rule: %v", err))
		return
	}
	
	// Apply to iptables if enabled
	if rule.Enabled {
		if err := s.applyVPNFirewallRule(r.Context(), rule); err != nil {
			// Log error but don't fail - rule is saved in DB
			fmt.Printf("Warning: failed to apply VPN firewall rule to iptables: %v\n", err)
		}
	}
	
	// Create audit log
	s.store.CreateFirewallAuditLog(r.Context(), "vpn_rule_created", map[string]interface{}{
		"rule_id":   rule.ID,
		"rule_name": rule.Name,
	}, r.RemoteAddr)
	
	// Fetch the rule with joined names
	createdRule, _ := s.store.GetVPNFirewallRule(r.Context(), rule.ID)
	if createdRule != nil {
		rule = createdRule
	}
	
	jsonResponse(w, http.StatusCreated, rule)
}

// handleVPNFirewallUpdateRule updates an existing VPN firewall rule
func (s *Server) handleVPNFirewallUpdateRule(w http.ResponseWriter, r *http.Request) {
	id := mux.Vars(r)["id"]
	
	// Check if rule exists
	existingRule, err := s.store.GetVPNFirewallRule(r.Context(), id)
	if err != nil {
		errorResponse(w, http.StatusInternalServerError, fmt.Sprintf("failed to get rule: %v", err))
		return
	}
	if existingRule == nil {
		errorResponse(w, http.StatusNotFound, "rule not found")
		return
	}
	
	var req VPNFirewallRuleRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		errorResponse(w, http.StatusBadRequest, "invalid request body")
		return
	}
	
	// Validate the request
	if err := validateVPNFirewallRule(&req); err != nil {
		errorResponse(w, http.StatusBadRequest, err.Error())
		return
	}
	
	// Update the rule model
	rule := &models.VPNFirewallRule{
		ID:              id,
		Name:            req.Name,
		Description:     req.Description,
		SourceType:      req.SourceType,
		SourceNetworkID: req.SourceNetworkID,
		SourceNodeID:    req.SourceNodeID,
		SourceIP:        req.SourceIP,
		DestType:        req.DestType,
		DestNetworkID:   req.DestNetworkID,
		DestNodeID:      req.DestNodeID,
		DestIP:          req.DestIP,
		Protocol:        req.Protocol,
		Port:            req.Port,
		Action:          req.Action,
		Priority:        req.Priority,
		Enabled:         req.Enabled,
	}
	
	// Update in database
	if err := s.store.UpdateVPNFirewallRule(r.Context(), rule); err != nil {
		errorResponse(w, http.StatusInternalServerError, fmt.Sprintf("failed to update VPN firewall rule: %v", err))
		return
	}
	
	// Re-apply all VPN firewall rules to iptables
	if err := s.syncVPNFirewallRules(r.Context()); err != nil {
		fmt.Printf("Warning: failed to sync VPN firewall rules to iptables: %v\n", err)
	}
	
	// Create audit log
	s.store.CreateFirewallAuditLog(r.Context(), "vpn_rule_updated", map[string]interface{}{
		"rule_id":   rule.ID,
		"rule_name": rule.Name,
	}, r.RemoteAddr)
	
	// Fetch the rule with joined names
	updatedRule, _ := s.store.GetVPNFirewallRule(r.Context(), rule.ID)
	if updatedRule != nil {
		rule = updatedRule
	}
	
	jsonResponse(w, http.StatusOK, rule)
}

// handleVPNFirewallDeleteRule deletes a VPN firewall rule
func (s *Server) handleVPNFirewallDeleteRule(w http.ResponseWriter, r *http.Request) {
	id := mux.Vars(r)["id"]
	
	// Check if rule exists
	existingRule, err := s.store.GetVPNFirewallRule(r.Context(), id)
	if err != nil {
		errorResponse(w, http.StatusInternalServerError, fmt.Sprintf("failed to get rule: %v", err))
		return
	}
	if existingRule == nil {
		errorResponse(w, http.StatusNotFound, "rule not found")
		return
	}
	
	// Delete from database
	if err := s.store.DeleteVPNFirewallRule(r.Context(), id); err != nil {
		errorResponse(w, http.StatusInternalServerError, fmt.Sprintf("failed to delete VPN firewall rule: %v", err))
		return
	}
	
	// Re-sync all VPN firewall rules to iptables (removes deleted rule)
	if err := s.syncVPNFirewallRules(r.Context()); err != nil {
		fmt.Printf("Warning: failed to sync VPN firewall rules to iptables: %v\n", err)
	}
	
	// Create audit log
	s.store.CreateFirewallAuditLog(r.Context(), "vpn_rule_deleted", map[string]interface{}{
		"rule_id":   id,
		"rule_name": existingRule.Name,
	}, r.RemoteAddr)
	
	w.WriteHeader(http.StatusNoContent)
}

// handleVPNFirewallApply syncs all database rules to iptables FORWARD chain
func (s *Server) handleVPNFirewallApply(w http.ResponseWriter, r *http.Request) {
	if err := s.syncVPNFirewallRules(r.Context()); err != nil {
		errorResponse(w, http.StatusInternalServerError, fmt.Sprintf("failed to apply VPN firewall rules: %v", err))
		return
	}
	
	// Create audit log
	s.store.CreateFirewallAuditLog(r.Context(), "vpn_rules_applied", map[string]interface{}{
		"action": "full_sync",
	}, r.RemoteAddr)
	
	jsonResponse(w, http.StatusOK, map[string]interface{}{
		"status":  "success",
		"message": "VPN firewall rules applied successfully",
	})
}

// applyVPNFirewallRule applies a single VPN firewall rule to iptables
func (s *Server) applyVPNFirewallRule(ctx context.Context, rule *models.VPNFirewallRule) error {
	// Build source IP/CIDR
	sourceIP, err := s.resolveVPNRuleEndpoint(ctx, rule.SourceType, rule.SourceNetworkID, rule.SourceNodeID, rule.SourceIP)
	if err != nil {
		return fmt.Errorf("failed to resolve source: %w", err)
	}
	
	// Build destination IP/CIDR
	destIP, err := s.resolveVPNRuleEndpoint(ctx, rule.DestType, rule.DestNetworkID, rule.DestNodeID, rule.DestIP)
	if err != nil {
		return fmt.Errorf("failed to resolve destination: %w", err)
	}
	
	// Build iptables command
	args := []string{"-A", "FORWARD"}
	
	// Add source
	if sourceIP != "" && sourceIP != "0.0.0.0/0" {
		args = append(args, "-s", sourceIP)
	}
	
	// Add destination
	if destIP != "" && destIP != "0.0.0.0/0" {
		args = append(args, "-d", destIP)
	}
	
	// Add protocol
	if rule.Protocol != "all" && rule.Protocol != "" {
		args = append(args, "-p", rule.Protocol)
		
		// Add port (only for tcp/udp)
		if rule.Port != "" && (rule.Protocol == "tcp" || rule.Protocol == "udp") {
			if strings.Contains(rule.Port, ",") {
				args = append(args, "-m", "multiport", "--dports", rule.Port)
			} else {
				args = append(args, "--dport", rule.Port)
			}
		}
	}
	
	// Add action
	target := strings.ToUpper(rule.Action)
	args = append(args, "-j", target)
	
	// Add comment with rule ID for identification
	args = append(args, "-m", "comment", "--comment", fmt.Sprintf("novusgate-vpn-%s", rule.ID))
	
	// Execute iptables command
	_, err = execHostCommand("iptables", args...)
	if err != nil {
		return fmt.Errorf("iptables command failed: %w", err)
	}
	
	return nil
}

// resolveVPNRuleEndpoint resolves the IP/CIDR for a VPN rule endpoint
func (s *Server) resolveVPNRuleEndpoint(ctx context.Context, endpointType string, networkID, nodeID *string, customIP string) (string, error) {
	switch endpointType {
	case "any":
		return "0.0.0.0/0", nil
	case "network":
		if networkID == nil {
			return "", fmt.Errorf("network_id is required for network type")
		}
		network, err := s.store.GetNetwork(ctx, *networkID)
		if err != nil {
			return "", err
		}
		if network == nil {
			return "", fmt.Errorf("network not found")
		}
		return network.CIDR, nil
	case "node":
		if nodeID == nil {
			return "", fmt.Errorf("node_id is required for node type")
		}
		node, err := s.store.GetNode(ctx, *nodeID)
		if err != nil {
			return "", err
		}
		if node == nil {
			return "", fmt.Errorf("node not found")
		}
		return node.VirtualIP.String() + "/32", nil
	case "custom":
		if customIP == "" {
			return "", fmt.Errorf("custom IP is required for custom type")
		}
		// Ensure CIDR notation
		if !strings.Contains(customIP, "/") {
			customIP = customIP + "/32"
		}
		return customIP, nil
	default:
		return "", fmt.Errorf("unknown endpoint type: %s", endpointType)
	}
}

// syncVPNFirewallRules syncs all database rules to iptables FORWARD chain
func (s *Server) syncVPNFirewallRules(ctx context.Context) error {
	// First, remove all existing NovusGate VPN rules from FORWARD chain
	// We identify them by the comment "novusgate-vpn-*"
	if err := s.clearNovusGateVPNRules(); err != nil {
		return fmt.Errorf("failed to clear existing VPN rules: %w", err)
	}
	
	// Get all enabled rules from database
	rules, err := s.store.ListVPNFirewallRules(ctx)
	if err != nil {
		return fmt.Errorf("failed to list VPN firewall rules: %w", err)
	}
	
	// Apply each enabled rule
	for _, rule := range rules {
		if !rule.Enabled {
			continue
		}
		
		if err := s.applyVPNFirewallRule(ctx, rule); err != nil {
			fmt.Printf("Warning: failed to apply VPN rule %s: %v\n", rule.Name, err)
			// Continue with other rules
		}
	}
	
	// Update WireGuard peer AllowedIPs based on VPN firewall rules
	if err := s.syncPeerAllowedIPs(ctx, rules); err != nil {
		fmt.Printf("Warning: failed to sync peer AllowedIPs: %v\n", err)
	}
	
	// Save rules with netfilter-persistent
	execHostCommand("netfilter-persistent", "save")
	
	return nil
}

// syncPeerAllowedIPs updates WireGuard peer AllowedIPs based on VPN firewall rules
// This allows traffic between networks when firewall rules permit it
func (s *Server) syncPeerAllowedIPs(ctx context.Context, rules []*models.VPNFirewallRule) error {
	// Get all networks
	networks, err := s.store.ListNetworks(ctx)
	if err != nil {
		return fmt.Errorf("failed to list networks: %w", err)
	}
	
	// Build a map of network ID to CIDR
	networkCIDRs := make(map[string]string)
	for _, net := range networks {
		networkCIDRs[net.ID] = net.CIDR
	}
	
	// For each network, determine which other networks it should be able to reach
	// based on enabled ACCEPT rules
	networkRoutes := make(map[string]map[string]bool) // networkID -> set of CIDRs to route
	
	for _, rule := range rules {
		if !rule.Enabled || rule.Action != "accept" {
			continue
		}
		
		// Get source and destination network CIDRs
		var sourceCIDRs, destCIDRs []string
		
		switch rule.SourceType {
		case "any":
			// All networks
			for _, cidr := range networkCIDRs {
				sourceCIDRs = append(sourceCIDRs, cidr)
			}
		case "network":
			if rule.SourceNetworkID != nil {
				if cidr, ok := networkCIDRs[*rule.SourceNetworkID]; ok {
					sourceCIDRs = append(sourceCIDRs, cidr)
				}
			}
		case "node":
			// For node, we need to find its network
			if rule.SourceNodeID != nil {
				node, _ := s.store.GetNode(ctx, *rule.SourceNodeID)
				if node != nil {
					if cidr, ok := networkCIDRs[node.NetworkID]; ok {
						sourceCIDRs = append(sourceCIDRs, cidr)
					}
				}
			}
		}
		
		switch rule.DestType {
		case "any":
			for _, cidr := range networkCIDRs {
				destCIDRs = append(destCIDRs, cidr)
			}
		case "network":
			if rule.DestNetworkID != nil {
				if cidr, ok := networkCIDRs[*rule.DestNetworkID]; ok {
					destCIDRs = append(destCIDRs, cidr)
				}
			}
		case "node":
			if rule.DestNodeID != nil {
				node, _ := s.store.GetNode(ctx, *rule.DestNodeID)
				if node != nil {
					if cidr, ok := networkCIDRs[node.NetworkID]; ok {
						destCIDRs = append(destCIDRs, cidr)
					}
				}
			}
		}
		
		// For each source network, add destination CIDRs to its routes
		for _, srcCIDR := range sourceCIDRs {
			// Find network ID by CIDR
			var srcNetID string
			for id, cidr := range networkCIDRs {
				if cidr == srcCIDR {
					srcNetID = id
					break
				}
			}
			if srcNetID == "" {
				continue
			}
			
			if networkRoutes[srcNetID] == nil {
				networkRoutes[srcNetID] = make(map[string]bool)
			}
			for _, destCIDR := range destCIDRs {
				networkRoutes[srcNetID][destCIDR] = true
			}
		}
	}
	
	// Now update each network's peers with the combined AllowedIPs
	for netID, routes := range networkRoutes {
		network, err := s.store.GetNetwork(ctx, netID)
		if err != nil || network == nil {
			continue
		}
		
		// Get all nodes in this network
		nodes, err := s.store.ListNodes(ctx, netID)
		if err != nil {
			continue
		}
		
		// Build AllowedIPs string: own network + all routed networks
		allowedCIDRs := []string{network.CIDR}
		for cidr := range routes {
			if cidr != network.CIDR {
				allowedCIDRs = append(allowedCIDRs, cidr)
			}
		}
		allowedIPsStr := strings.Join(allowedCIDRs, ",")
		
		// Update each node's peer entry on the server
		mgr := s.getManager(netID)
		if mgr == nil {
			continue
		}
		
		for _, node := range nodes {
			// Update peer's AllowedIPs to include all routed networks
			nodeAllowedIPs := node.VirtualIP.String() + "/32"
			// Note: On server side, peer AllowedIPs is just the node's IP
			// The routing happens via iptables FORWARD rules
			// But we need to ensure IP forwarding is enabled
			if err := mgr.UpdatePeerAllowedIPs(node.PublicKey, nodeAllowedIPs); err != nil {
				fmt.Printf("Warning: failed to update peer %s AllowedIPs: %v\n", node.Name, err)
			}
		}
		
		fmt.Printf("[VPN Firewall] Network %s can now route to: %s\n", network.Name, allowedIPsStr)
	}
	
	// Ensure IP forwarding is enabled
	execHostCommand("sysctl", "-w", "net.ipv4.ip_forward=1")
	
	return nil
}

// clearNovusGateVPNRules removes all NovusGate VPN rules from FORWARD chain
func (s *Server) clearNovusGateVPNRules() error {
	// Get current FORWARD chain rules
	output, err := execHostCommand("iptables", "-L", "FORWARD", "-n", "-v", "--line-numbers")
	if err != nil {
		return err
	}
	
	// Find all rules with novusgate-vpn comment and delete them (in reverse order)
	lines := strings.Split(output, "\n")
	var lineNumbers []int
	
	for _, line := range lines {
		if strings.Contains(line, "novusgate-vpn-") {
			fields := strings.Fields(line)
			if len(fields) > 0 {
				if num, err := strconv.Atoi(fields[0]); err == nil {
					lineNumbers = append(lineNumbers, num)
				}
			}
		}
	}
	
	// Delete in reverse order to maintain line numbers
	for i := len(lineNumbers) - 1; i >= 0; i-- {
		execHostCommand("iptables", "-D", "FORWARD", strconv.Itoa(lineNumbers[i]))
	}
	
	return nil
}
