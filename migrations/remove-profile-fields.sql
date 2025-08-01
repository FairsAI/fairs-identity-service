-- Migration: Remove profile fields from Identity Service
-- Date: 2025-08-01
-- Purpose: Profile data now managed by Profile Service
-- 
-- This migration removes profile-related fields from the Identity Service
-- as part of the pre-launch architecture cleanup.

-- Begin transaction
BEGIN;

-- Step 1: Drop profile-related columns from users table
ALTER TABLE identity_service.users 
    DROP COLUMN IF EXISTS first_name,
    DROP COLUMN IF EXISTS last_name,
    DROP COLUMN IF EXISTS phone;

-- Step 2: Add comment to document the change
COMMENT ON TABLE identity_service.users IS 
    'Core user identity table. Profile data (name, phone, preferences) now managed by Profile Service.';

-- Step 3: Update any views that might reference these columns
-- (None found in current schema)

-- Step 4: Log the migration (if schema_migrations table exists)
-- Uncomment if your database has a migrations tracking table:
-- INSERT INTO identity_service.schema_migrations (version, description, executed_at)
-- VALUES ('20250801_remove_profile_fields', 'Remove profile fields - data now in Profile Service', NOW())
-- ON CONFLICT (version) DO NOTHING;

-- Commit the changes
COMMIT;

-- Note: Before running this migration in production:
-- 1. Ensure all profile data has been migrated to Profile Service
-- 2. Update all services to use Profile Service for profile data
-- 3. Test that no services are still trying to access these fields