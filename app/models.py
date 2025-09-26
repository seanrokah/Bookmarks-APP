from datetime import datetime
from flask_sqlalchemy import SQLAlchemy
from sqlalchemy import Index, text
from sqlalchemy.dialects.postgresql import TSVECTOR
from argon2 import PasswordHasher
from argon2.exceptions import VerifyMismatchError

db = SQLAlchemy()
ph = PasswordHasher()


class User(db.Model):
    __tablename__ = 'users'
    
    id = db.Column(db.Integer, primary_key=True)
    email = db.Column(db.String(255), unique=True, nullable=False, index=True)
    password_hash = db.Column(db.String(255), nullable=False)
    display_name = db.Column(db.String(120))
    is_admin = db.Column(db.Boolean, default=False, nullable=False)
    created_at = db.Column(db.DateTime(timezone=True), default=datetime.utcnow)
    
    # Relationships
    bookmarks = db.relationship('Bookmark', backref='user', lazy='dynamic', cascade='all, delete-orphan')
    categories = db.relationship('Category', backref='user', lazy='dynamic', cascade='all, delete-orphan')
    tags = db.relationship('Tag', backref='user', lazy='dynamic', cascade='all, delete-orphan')
    
    def set_password(self, password):
        """Hash and set password."""
        self.password_hash = ph.hash(password)
    
    def check_password(self, password):
        """Check if provided password matches hash."""
        try:
            ph.verify(self.password_hash, password)
            return True
        except VerifyMismatchError:
            return False
    
    def to_dict(self):
        return {
            'id': self.id,
            'email': self.email,
            'display_name': self.display_name,
            'is_admin': self.is_admin,
            'created_at': self.created_at.isoformat() if self.created_at else None
        }


class Category(db.Model):
    __tablename__ = 'categories'
    
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('users.id'), nullable=False, index=True)
    name = db.Column(db.String(120), nullable=False)
    parent_id = db.Column(db.Integer, db.ForeignKey('categories.id'))
    created_at = db.Column(db.DateTime(timezone=True), default=datetime.utcnow)
    
    # Self-referential relationship for hierarchy
    children = db.relationship('Category', backref=db.backref('parent', remote_side=[id]))
    
    # Relationships
    bookmarks = db.relationship('Bookmark', backref='category', lazy='dynamic')
    
    def to_dict(self, include_children=False):
        result = {
            'id': self.id,
            'name': self.name,
            'parent_id': self.parent_id,
            'created_at': self.created_at.isoformat() if self.created_at else None,
            'bookmark_count': self.bookmarks.filter_by(is_archived=False).count()
        }
        if include_children:
            result['children'] = [child.to_dict(include_children=True) for child in self.children]
        return result


class Tag(db.Model):
    __tablename__ = 'tags'
    
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('users.id'), nullable=False, index=True)
    name = db.Column(db.String(64), nullable=False, index=True)
    created_at = db.Column(db.DateTime(timezone=True), default=datetime.utcnow)
    
    def to_dict(self):
        return {
            'id': self.id,
            'name': self.name,
            'created_at': self.created_at.isoformat() if self.created_at else None
        }


# Association table for bookmark tags
bookmark_tags = db.Table('bookmark_tags',
    db.Column('bookmark_id', db.Integer, db.ForeignKey('bookmarks.id'), primary_key=True),
    db.Column('tag_id', db.Integer, db.ForeignKey('tags.id'), primary_key=True)
)


class Bookmark(db.Model):
    __tablename__ = 'bookmarks'
    
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('users.id'), nullable=False, index=True)
    category_id = db.Column(db.Integer, db.ForeignKey('categories.id'), index=True)
    url = db.Column(db.Text, nullable=False, index=True)
    title = db.Column(db.String(512))
    note_md = db.Column(db.Text)
    og_title = db.Column(db.String(512))
    og_description = db.Column(db.Text)
    favicon_url = db.Column(db.Text)
    is_archived = db.Column(db.Boolean, default=False, nullable=False)
    created_at = db.Column(db.DateTime(timezone=True), default=datetime.utcnow, index=True)
    updated_at = db.Column(db.DateTime(timezone=True), default=datetime.utcnow, onupdate=datetime.utcnow)
    
    # Full-text search vector
    search_vector = db.Column(TSVECTOR)
    
    # Relationships
    tags = db.relationship('Tag', secondary=bookmark_tags, backref='bookmarks')
    
    def to_dict(self, include_tags=True):
        result = {
            'id': self.id,
            'url': self.url,
            'title': self.title,
            'note_md': self.note_md,
            'og_title': self.og_title,
            'og_description': self.og_description,
            'favicon_url': self.favicon_url,
            'is_archived': self.is_archived,
            'category_id': self.category_id,
            'created_at': self.created_at.isoformat() if self.created_at else None,
            'updated_at': self.updated_at.isoformat() if self.updated_at else None
        }
        if include_tags:
            result['tags'] = [tag.to_dict() for tag in self.tags]
        if self.category:
            result['category'] = self.category.to_dict()
        return result


# Create database indexes
Index('idx_bookmarks_user_category', Bookmark.user_id, Bookmark.category_id)
Index('idx_bookmarks_search', Bookmark.search_vector, postgresql_using='gin')
Index('idx_bookmarks_user_created', Bookmark.user_id, Bookmark.created_at.desc())

# Unique constraint for user tags
Index('idx_tags_user_name_unique', Tag.user_id, Tag.name, unique=True)
Index('idx_categories_user_name_unique', Category.user_id, Category.name, unique=True)
