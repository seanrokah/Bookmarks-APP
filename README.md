# Bookmark Master

A self-hosted web application for organizing and managing bookmarks with categories, tags, search, and a beautiful dashboard.

## Features

- **User Authentication**: Secure user registration and login with password hashing
- **Bookmark Management**: Save, organize, edit, and delete bookmarks
- **Categories & Tags**: Hierarchical categories and flexible tagging system
- **Advanced Search**: Full-text search with filtering by category, tags, and date
- **Bulk Import**: Import multiple bookmarks at once
- **Metadata Enrichment**: Automatic fetching of page titles, descriptions, and favicons
- **Beautiful UI**: Modern, responsive design with dark mode support
- **Fast Redirects**: Short URLs for quick bookmark access (`/r/<id>`)
- **Dashboard**: Customizable dashboard with statistics and recent bookmarks

## Architecture

- **NGINX**: Reverse proxy with TLS termination and static file serving
- **Flask**: Python web application with Gunicorn WSGI server
- **PostgreSQL**: Database with full-text search capabilities
- **Docker Compose**: Easy deployment and management

## Quick Start

1. **Clone the repository:**
   ```bash
   git clone <repository-url>
   cd Bookmark_App
   ```

2. **Configure environment variables:**
   ```bash
   cp .env.example .env
   # Edit .env with your configuration
   ```

3. **Start the application:**
   ```bash
   docker-compose up -d
   ```

4. **Access the application:**
   - Open http://localhost in your browser
   - Register a new account
   - Start adding bookmarks!

## Configuration

### Environment Variables

- `DATABASE_URL`: PostgreSQL connection string
- `SECRET_KEY`: Flask secret key for sessions
- `JWT_SECRET_KEY`: JWT signing key
- `ENABLE_REGISTRATION`: Allow new user registration (default: true)
- `METADATA_FETCH_TIMEOUT`: Timeout for fetching page metadata (default: 10s)

### SSL/HTTPS Setup

To enable HTTPS:

1. Place SSL certificates in `nginx/ssl/`:
   - `cert.pem`: SSL certificate
   - `key.pem`: Private key

2. Uncomment the HTTPS server block in `nginx/nginx.conf`

3. Update the HTTP server to redirect to HTTPS

## API Documentation

### Authentication

- `POST /api/v1/auth/register` - Register new user
- `POST /api/v1/auth/login` - Login user
- `POST /api/v1/auth/refresh` - Refresh access token
- `GET /api/v1/auth/me` - Get current user
- `POST /api/v1/auth/change-password` - Change password

### Bookmarks

- `GET /api/v1/bookmarks` - List bookmarks with filtering and search
- `POST /api/v1/bookmarks` - Create bookmark
- `POST /api/v1/bookmarks/bulk` - Bulk create bookmarks
- `GET /api/v1/bookmarks/{id}` - Get bookmark
- `PATCH /api/v1/bookmarks/{id}` - Update bookmark
- `DELETE /api/v1/bookmarks/{id}` - Delete bookmark
- `GET /r/{id}` - Redirect to bookmark URL

### Categories

- `GET /api/v1/categories/tree` - Get categories tree
- `POST /api/v1/categories` - Create category
- `PATCH /api/v1/categories/{id}` - Update category
- `DELETE /api/v1/categories/{id}` - Delete category

### Tags

- `GET /api/v1/tags` - List tags
- `POST /api/v1/tags` - Create tag
- `DELETE /api/v1/tags/{id}` - Delete tag

## Database Schema

### Users
- Authentication and profile information
- Password hashing with Argon2id

### Categories
- Hierarchical organization (parent/child relationships)
- User-scoped categories

### Tags
- Flexible tagging system
- Many-to-many relationship with bookmarks

### Bookmarks
- URL, title, notes, and metadata
- Full-text search with PostgreSQL
- Automatic metadata enrichment

## Security Features

- Password hashing with Argon2id
- JWT-based authentication
- Rate limiting on API endpoints
- CSRF protection
- Input validation and sanitization
- Security headers (HSTS, CSP, etc.)
- SQL injection protection with SQLAlchemy

## Development

### Local Development

1. **Install dependencies:**
   ```bash
   cd app
   pip install -r requirements.txt
   ```

2. **Set up database:**
   ```bash
   # Start PostgreSQL
   docker run -d --name postgres -e POSTGRES_DB=bookmarks -e POSTGRES_USER=bookmarks -e POSTGRES_PASSWORD=bookmarks -p 5432:5432 postgres:15-alpine
   ```

3. **Run the application:**
   ```bash
   export FLASK_ENV=development
   export DATABASE_URL=postgresql://bookmarks:bookmarks@localhost:5432/bookmarks
   python wsgi.py
   ```

### Testing

```bash
# Run tests (when implemented)
python -m pytest tests/
```

### Database Migrations

```bash
# Create migration
flask db migrate -m "Description"

# Apply migration
flask db upgrade
```

## Production Deployment

### Docker Compose (Recommended)

```bash
# Production deployment
docker-compose -f docker-compose.yml -f docker-compose.prod.yml up -d
```

### Manual Deployment

1. Set up PostgreSQL database
2. Configure NGINX reverse proxy
3. Deploy Flask application with Gunicorn
4. Set up SSL certificates
5. Configure environment variables

## Monitoring

- Health check endpoint: `/health`
- NGINX access logs
- Application logs via Docker
- Database monitoring with PostgreSQL tools

## Backup

### Database Backup

```bash
# Create backup
docker exec postgres pg_dump -U bookmarks bookmarks > backup.sql

# Restore backup
docker exec -i postgres psql -U bookmarks bookmarks < backup.sql
```

### Full Backup

```bash
# Backup all data including uploads
tar -czf bookmark-backup.tar.gz postgres_data/ nginx/ssl/
```

## Contributing

1. Fork the repository
2. Create a feature branch
3. Make your changes
4. Add tests
5. Submit a pull request

## License

This project is licensed under the MIT License - see the LICENSE file for details.

## Support

For issues and feature requests, please use the GitHub issue tracker.
