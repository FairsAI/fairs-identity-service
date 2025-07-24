-- Add fields to support guest-to-member conversion (Best Practice Implementation)

-- Add guest status tracking
ALTER TABLE identity_service.users 
ADD COLUMN IF NOT EXISTS is_guest BOOLEAN DEFAULT false;

-- Add member conversion timestamp
ALTER TABLE identity_service.users 
ADD COLUMN IF NOT EXISTS member_converted_at TIMESTAMP WITH TIME ZONE NULL;

-- Add original guest ID tracking for audit trail
ALTER TABLE identity_service.users 
ADD COLUMN IF NOT EXISTS original_guest_id VARCHAR(100) NULL;

-- Add indexes for performance
CREATE INDEX IF NOT EXISTS idx_users_is_guest ON identity_service.users(is_guest);
CREATE INDEX IF NOT EXISTS idx_users_member_converted ON identity_service.users(member_converted_at);
CREATE INDEX IF NOT EXISTS idx_users_original_guest_id ON identity_service.users(original_guest_id);

-- Add comments for documentation
COMMENT ON COLUMN identity_service.users.is_guest IS 'Indicates if user is currently in guest status (false = authenticated member)';
COMMENT ON COLUMN identity_service.users.member_converted_at IS 'Timestamp when guest user was converted to authenticated member';
COMMENT ON COLUMN identity_service.users.original_guest_id IS 'Original guest session ID for audit trail of conversions';