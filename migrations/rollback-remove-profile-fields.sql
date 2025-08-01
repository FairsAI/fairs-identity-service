-- Rollback Migration: Restore profile fields to Identity Service
-- Date: 2025-08-01
-- Purpose: Rollback script in case we need to revert the profile field removal
-- 
-- WARNING: This will only restore the schema, not the data!
-- Data recovery would need to be done from backups or Profile Service.

-- Begin transaction
BEGIN;

-- Step 1: Re-add profile-related columns to users table
ALTER TABLE identity_service.users 
    ADD COLUMN IF NOT EXISTS first_name VARCHAR(100),
    ADD COLUMN IF NOT EXISTS last_name VARCHAR(100),
    ADD COLUMN IF NOT EXISTS phone VARCHAR(20);

-- Step 2: Restore original comment
COMMENT ON TABLE identity_service.users IS 
    'User identity and authentication data';

-- Step 3: Log the rollback (if schema_migrations table exists)
-- Uncomment if your database has a migrations tracking table:
-- DELETE FROM identity_service.schema_migrations 
-- WHERE version = '20250801_remove_profile_fields';

-- Commit the changes
COMMIT;

-- Note: After running this rollback:
-- 1. You'll need to restore the data from backups or Profile Service
-- 2. Update services to use these fields again
-- 3. Ensure data consistency between Identity and Profile services