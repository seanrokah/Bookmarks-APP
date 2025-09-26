#!/bin/bash

# Bookmark Master Setup Script

echo "🔖 Setting up Bookmark Master..."

# Check if Docker and Docker Compose are installed
if ! command -v docker &> /dev/null; then
    echo "❌ Docker is not installed. Please install Docker first."
    exit 1
fi

if ! command -v docker compose &> /dev/null; then
    echo "❌ Docker Compose is not installed. Please install Docker Compose first."
    exit 1
fi

# Create .env file if it doesn't exist
if [ ! -f .env ]; then
    echo "📝 Creating .env file..."
    cat > .env << EOF
# Database Configuration
DATABASE_URL=postgresql://bookmarks:bookmarks@db:5432/bookmarks

# Flask Configuration
FLASK_ENV=production
SECRET_KEY=$(openssl rand -base64 32)
JWT_SECRET_KEY=$(openssl rand -base64 32)

# Security
BCRYPT_LOG_ROUNDS=12

# Features
ENABLE_REGISTRATION=true
DEFAULT_THEME=light

# Metadata fetching
METADATA_FETCH_TIMEOUT=10
MAX_CONTENT_SIZE=1048576
EOF
    echo "✅ Created .env file with random secret keys"
else
    echo "ℹ️  Using existing .env file"
fi

# Create SSL directory for NGINX
mkdir -p nginx/ssl

# Build and start the application
echo "🏗️  Building and starting the application..."
docker compose up -d --build

# Wait for services to start
echo "⏳ Waiting for services to start..."
sleep 10

# Check if services are running
if docker compose ps | grep -q "Up"; then
    echo "✅ Services are running!"
    echo ""
    echo "🎉 Bookmark Master is ready!"
    echo ""
    echo "📖 Access your application:"
    echo "   Web Interface: http://localhost"
    echo "   API Documentation: Check README.md"
    echo ""
    echo "🔧 Next steps:"
    echo "   1. Open http://localhost in your browser"
    echo "   2. Register a new account"
    echo "   3. Start adding bookmarks!"
    echo ""
    echo "📁 Project structure:"
    echo "   - app/: Flask application"
    echo "   - nginx/: NGINX configuration"
    echo "   - db/: Database initialization"
    echo ""
    echo "🛠️  Useful commands:"
    echo "   Stop:    docker compose down"
    echo "   Logs:    docker compose logs -f"
    echo "   Backup:  docker exec postgres pg_dump -U bookmarks bookmarks > backup.sql"
    echo ""
else
    echo "❌ Some services failed to start. Check logs with:"
    echo "   docker compose logs"
fi
