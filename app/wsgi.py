"""WSGI entry point for the application."""

import os
from app import create_app
from models import db

# Create the Flask application
application = create_app()

# Initialize database on startup
with application.app_context():
    try:
        # Create all tables
        db.create_all()
        print("Database tables created successfully")
            
    except Exception as e:
        print(f"Database initialization error: {e}")

if __name__ == "__main__":
    application.run(host='0.0.0.0', port=5000, debug=True)
