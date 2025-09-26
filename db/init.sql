-- PostgreSQL initialization script
-- This runs when the database container starts for the first time

-- Enable required extensions
CREATE EXTENSION IF NOT EXISTS "pg_trgm";
CREATE EXTENSION IF NOT EXISTS "unaccent";

-- Create database if it doesn't exist (handled by Docker environment)
-- The POSTGRES_DB environment variable creates the database automatically

-- Grant necessary permissions
GRANT ALL PRIVILEGES ON DATABASE bookmarks TO bookmarks;

-- Note: Tables will be created by SQLAlchemy migrations when the Flask app starts
