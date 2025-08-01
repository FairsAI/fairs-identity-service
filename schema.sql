-- Fairs Identity Service Database Schema
-- Schema: identity_service

CREATE SCHEMA IF NOT EXISTS identity_service;
SET search_path TO identity_service, public;

-- Enable UUID extension for generating UUIDs
CREATE EXTENSION IF NOT EXISTS "uuid-ossp";

-- Users table for basic user information
CREATE TABLE users (
    id SERIAL PRIMARY KEY,
    email VARCHAR(255) UNIQUE NOT NULL,
    password_hash VARCHAR(255),
    is_guest BOOLEAN DEFAULT false,
    member_converted_at TIMESTAMP WITH TIME ZONE,
    created_at TIMESTAMP WITH TIME ZONE DEFAULT NOW(),
    updated_at TIMESTAMP WITH TIME ZONE DEFAULT NOW(),
    is_active BOOLEAN DEFAULT true
);

-- Device fingerprints table for storing device identification data
CREATE TABLE device_fingerprints (
    id SERIAL PRIMARY KEY,
    fingerprint_hash VARCHAR(64) UNIQUE NOT NULL,
    user_agent TEXT,
    screen_resolution VARCHAR(50),
    color_depth INTEGER,
    timezone VARCHAR(100),
    language_preferences VARCHAR(100),
    browser_plugins TEXT,
    installed_fonts TEXT,
    canvas_fingerprint TEXT,
    webgl_fingerprint TEXT,
    battery_info TEXT,
    device_memory INTEGER,
    hardware_concurrency INTEGER,
    platform VARCHAR(100),
    ip_address INET,
    connection_type VARCHAR(50),
    browser_version VARCHAR(100),
    os_version VARCHAR(100),
    is_mobile BOOLEAN DEFAULT false,
    network_info JSONB,
    metadata JSONB,
    confidence_score DECIMAL(3,2) DEFAULT 1.0,
    created_at TIMESTAMP WITH TIME ZONE DEFAULT NOW(),
    last_seen TIMESTAMP WITH TIME ZONE DEFAULT NOW(),
    is_active BOOLEAN DEFAULT true
);

-- Cross-merchant identities for linking users across different merchants
CREATE TABLE cross_merchant_identities (
    id SERIAL PRIMARY KEY,
    identity_key UUID UNIQUE NOT NULL DEFAULT uuid_generate_v4(),
    is_verified BOOLEAN DEFAULT false,
    verification_level VARCHAR(20) DEFAULT 'basic', -- basic, enhanced, verified
    associated_devices INTEGER[] DEFAULT '{}',
    metadata JSONB,
    created_at TIMESTAMP WITH TIME ZONE DEFAULT NOW(),
    updated_at TIMESTAMP WITH TIME ZONE DEFAULT NOW()
);

-- Device-user associations to link devices with universal user IDs
CREATE TABLE device_user_associations (
    id SERIAL PRIMARY KEY,
    device_id INTEGER REFERENCES device_fingerprints(id) ON DELETE CASCADE,
    user_id UUID REFERENCES cross_merchant_identities(identity_key) ON DELETE CASCADE,
    merchant_id VARCHAR(100) NOT NULL,
    confidence_score DECIMAL(3,2) DEFAULT 0.5,
    is_primary BOOLEAN DEFAULT false,
    status VARCHAR(20) DEFAULT 'active', -- active, inactive, suspended
    verification_level VARCHAR(20) DEFAULT 'unverified', -- unverified, basic, enhanced, verified
    created_at TIMESTAMP WITH TIME ZONE DEFAULT NOW(),
    last_used TIMESTAMP WITH TIME ZONE DEFAULT NOW(),
    UNIQUE(device_id, user_id, merchant_id)
);

-- Cross-merchant user mappings for linking merchant-specific user IDs to universal IDs
CREATE TABLE cross_merchant_users (
    id SERIAL PRIMARY KEY,
    universal_id UUID REFERENCES cross_merchant_identities(identity_key) ON DELETE CASCADE,
    merchant_id VARCHAR(100) NOT NULL,
    merchant_user_id VARCHAR(100) NOT NULL,
    confidence_score DECIMAL(3,2) DEFAULT 1.0,
    status VARCHAR(20) DEFAULT 'active', -- active, inactive, merged
    created_at TIMESTAMP WITH TIME ZONE DEFAULT NOW(),
    updated_at TIMESTAMP WITH TIME ZONE DEFAULT NOW(),
    UNIQUE(merchant_id, merchant_user_id)
);

-- Verification events for tracking identity verification attempts
CREATE TABLE verification_events (
    id SERIAL PRIMARY KEY,
    user_id UUID REFERENCES cross_merchant_identities(identity_key) ON DELETE CASCADE,
    merchant_id VARCHAR(100),
    verification_type VARCHAR(50) NOT NULL, -- email, phone, document, biometric, etc.
    verification_method VARCHAR(50), -- sms, email, app, manual, etc.
    successful BOOLEAN NOT NULL,
    device_id INTEGER REFERENCES device_fingerprints(id) ON DELETE SET NULL,
    confidence_score DECIMAL(3,2),
    ip_address INET,
    user_agent TEXT,
    session_id VARCHAR(100),
    error_message TEXT,
    metadata JSONB,
    timestamp TIMESTAMP WITH TIME ZONE DEFAULT NOW()
);

-- Indexes for performance optimization

-- Device fingerprints indexes
CREATE INDEX idx_device_fingerprints_hash ON device_fingerprints(fingerprint_hash);
CREATE INDEX idx_device_fingerprints_ip ON device_fingerprints(ip_address);
CREATE INDEX idx_device_fingerprints_last_seen ON device_fingerprints(last_seen DESC);
CREATE INDEX idx_device_fingerprints_created_at ON device_fingerprints(created_at DESC);
CREATE INDEX idx_device_fingerprints_user_agent ON device_fingerprints USING gin(to_tsvector('english', user_agent));

-- Cross-merchant identities indexes
CREATE INDEX idx_cross_merchant_identities_key ON cross_merchant_identities(identity_key);
CREATE INDEX idx_cross_merchant_identities_verified ON cross_merchant_identities(is_verified);

-- Device-user associations indexes
CREATE INDEX idx_device_user_associations_device ON device_user_associations(device_id);
CREATE INDEX idx_device_user_associations_user ON device_user_associations(user_id);
CREATE INDEX idx_device_user_associations_merchant ON device_user_associations(merchant_id);
CREATE INDEX idx_device_user_associations_status ON device_user_associations(status);
CREATE INDEX idx_device_user_associations_last_used ON device_user_associations(last_used DESC);

-- Cross-merchant users indexes
CREATE INDEX idx_cross_merchant_users_universal ON cross_merchant_users(universal_id);
CREATE INDEX idx_cross_merchant_users_merchant ON cross_merchant_users(merchant_id, merchant_user_id);

-- Verification events indexes
CREATE INDEX idx_verification_events_user ON verification_events(user_id);
CREATE INDEX idx_verification_events_merchant ON verification_events(merchant_id);
CREATE INDEX idx_verification_events_device ON verification_events(device_id);
CREATE INDEX idx_verification_events_timestamp ON verification_events(timestamp DESC);
CREATE INDEX idx_verification_events_type ON verification_events(verification_type);

-- Users table indexes
CREATE INDEX idx_users_email ON users(email);
CREATE INDEX idx_users_active ON users(is_active);

-- Functions and triggers for updating timestamps

-- Function to update the updated_at timestamp
CREATE OR REPLACE FUNCTION update_updated_at_column()
RETURNS TRIGGER AS $$
BEGIN
    NEW.updated_at = NOW();
    RETURN NEW;
END;
$$ language 'plpgsql';

-- Triggers for automatically updating updated_at timestamps
CREATE TRIGGER update_users_updated_at 
    BEFORE UPDATE ON users 
    FOR EACH ROW EXECUTE FUNCTION update_updated_at_column();

CREATE TRIGGER update_cross_merchant_identities_updated_at 
    BEFORE UPDATE ON cross_merchant_identities 
    FOR EACH ROW EXECUTE FUNCTION update_updated_at_column();

CREATE TRIGGER update_cross_merchant_users_updated_at 
    BEFORE UPDATE ON cross_merchant_users 
    FOR EACH ROW EXECUTE FUNCTION update_updated_at_column();

-- Views for common queries

-- View for active device-user associations with device details
CREATE VIEW active_device_users AS
SELECT 
    dua.id,
    dua.device_id,
    dua.user_id,
    dua.merchant_id,
    dua.confidence_score,
    dua.is_primary,
    dua.verification_level,
    dua.last_used,
    df.fingerprint_hash,
    df.user_agent,
    df.ip_address,
    df.platform,
    df.is_mobile,
    df.last_seen AS device_last_seen
FROM device_user_associations dua
JOIN device_fingerprints df ON dua.device_id = df.id
WHERE dua.status = 'active' AND df.is_active = true;

-- View for user verification summary
CREATE VIEW user_verification_summary AS
SELECT 
    cmi.identity_key,
    cmi.is_verified,
    cmi.verification_level,
    COUNT(ve.id) as total_verifications,
    COUNT(CASE WHEN ve.successful = true THEN 1 END) as successful_verifications,
    MAX(ve.timestamp) as last_verification_attempt,
    MAX(CASE WHEN ve.successful = true THEN ve.timestamp END) as last_successful_verification
FROM cross_merchant_identities cmi
LEFT JOIN verification_events ve ON cmi.identity_key = ve.user_id
GROUP BY cmi.identity_key, cmi.is_verified, cmi.verification_level;

-- Comments for documentation
COMMENT ON SCHEMA identity_service IS 'Schema for the Fairs Identity Service containing device fingerprinting and cross-merchant identity management tables';

COMMENT ON TABLE device_fingerprints IS 'Stores device fingerprint data for device identification and tracking';
COMMENT ON TABLE cross_merchant_identities IS 'Universal user identities that span across multiple merchants';
COMMENT ON TABLE device_user_associations IS 'Links devices to universal user identities with merchant-specific context';
COMMENT ON TABLE cross_merchant_users IS 'Maps merchant-specific user IDs to universal identities';
COMMENT ON TABLE verification_events IS 'Tracks identity verification attempts and results';
COMMENT ON TABLE users IS 'Core user identity table. Profile data (name, phone, preferences) now managed by Profile Service.';

-- Sample data (optional - remove in production)
-- INSERT INTO cross_merchant_identities (identity_key) VALUES (uuid_generate_v4());

-- Reset search path to default
-- SET search_path TO public; 