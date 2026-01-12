-- Migration: 005_firewall_tables.sql
-- Purpose: Add firewall management tables for VPN traffic control

-- VPN Firewall Rules table
CREATE TABLE IF NOT EXISTS firewall_rules (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    name VARCHAR(255) NOT NULL,
    description TEXT,
    
    -- Source configuration
    source_type VARCHAR(20) NOT NULL CHECK (source_type IN ('any', 'network', 'node', 'custom')),
    source_network_id UUID REFERENCES networks(id) ON DELETE CASCADE,
    source_node_id UUID REFERENCES nodes(id) ON DELETE CASCADE,
    source_ip VARCHAR(50),
    
    -- Destination configuration
    dest_type VARCHAR(20) NOT NULL CHECK (dest_type IN ('any', 'network', 'node', 'custom')),
    dest_network_id UUID REFERENCES networks(id) ON DELETE CASCADE,
    dest_node_id UUID REFERENCES nodes(id) ON DELETE CASCADE,
    dest_ip VARCHAR(50),
    
    -- Rule details
    protocol VARCHAR(10) DEFAULT 'all' CHECK (protocol IN ('tcp', 'udp', 'icmp', 'all')),
    port VARCHAR(50),
    action VARCHAR(10) NOT NULL CHECK (action IN ('accept', 'drop', 'reject')),
    
    -- Metadata
    priority INT DEFAULT 100,
    enabled BOOLEAN DEFAULT true,
    created_at TIMESTAMP WITH TIME ZONE DEFAULT NOW(),
    updated_at TIMESTAMP WITH TIME ZONE DEFAULT NOW()
);

-- Audit log for firewall changes
CREATE TABLE IF NOT EXISTS firewall_audit_log (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    action VARCHAR(50) NOT NULL,
    details JSONB,
    user_ip VARCHAR(50),
    created_at TIMESTAMP WITH TIME ZONE DEFAULT NOW()
);

-- Indexes for better query performance
CREATE INDEX IF NOT EXISTS idx_firewall_rules_enabled ON firewall_rules(enabled);
CREATE INDEX IF NOT EXISTS idx_firewall_rules_priority ON firewall_rules(priority);
CREATE INDEX IF NOT EXISTS idx_firewall_rules_source_network ON firewall_rules(source_network_id);
CREATE INDEX IF NOT EXISTS idx_firewall_rules_dest_network ON firewall_rules(dest_network_id);
CREATE INDEX IF NOT EXISTS idx_firewall_audit_created ON firewall_audit_log(created_at);

-- Apply updated_at trigger to firewall_rules table
DROP TRIGGER IF EXISTS update_firewall_rules_updated_at ON firewall_rules;
CREATE TRIGGER update_firewall_rules_updated_at
    BEFORE UPDATE ON firewall_rules
    FOR EACH ROW
    EXECUTE FUNCTION update_updated_at_column();
