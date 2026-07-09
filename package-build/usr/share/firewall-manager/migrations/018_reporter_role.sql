-- Migration: 018_reporter_role
-- Description: Add 'reporter' role to user_role enum
-- Forked from LPM 015.

DO $$
BEGIN
    IF NOT EXISTS (
        SELECT 1 FROM pg_enum e
        JOIN pg_type t ON t.oid = e.enumtypid
        WHERE t.typname = 'user_role' AND e.enumlabel = 'reporter'
    ) THEN
        ALTER TYPE user_role ADD VALUE 'reporter';
    END IF;
END
$$;