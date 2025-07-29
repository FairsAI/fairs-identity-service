-- Add separate default shipping and billing columns to user_addresses table
-- This migration adds the missing columns that the repository expects

ALTER TABLE identity_service.user_addresses
ADD COLUMN IF NOT EXISTS is_default_shipping BOOLEAN DEFAULT false,
ADD COLUMN IF NOT EXISTS is_default_billing BOOLEAN DEFAULT false;

-- Migrate existing is_default values to both columns
UPDATE identity_service.user_addresses
SET is_default_shipping = is_default,
    is_default_billing = is_default
WHERE is_default = true;

-- Create indexes for better performance
CREATE INDEX IF NOT EXISTS idx_user_addresses_default_shipping 
ON identity_service.user_addresses(user_id, is_default_shipping) 
WHERE is_default_shipping = true;

CREATE INDEX IF NOT EXISTS idx_user_addresses_default_billing 
ON identity_service.user_addresses(user_id, is_default_billing) 
WHERE is_default_billing = true;

-- Add comments
COMMENT ON COLUMN identity_service.user_addresses.is_default_shipping IS 'Whether this is the default shipping address for the user';
COMMENT ON COLUMN identity_service.user_addresses.is_default_billing IS 'Whether this is the default billing address for the user';