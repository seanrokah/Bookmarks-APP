from flask import Blueprint, request, jsonify, current_app, redirect
from flask_jwt_extended import jwt_required, get_jwt_identity
from sqlalchemy import text, or_, and_
from models import db, Bookmark, Category, Tag, User
from utils import normalize_url, validate_url, fetch_metadata, sanitize_tag_name, parse_bulk_urls
import threading
from datetime import datetime

api_bp = Blueprint('api', __name__)


def get_current_user():
    """Get current authenticated user."""
    user_id = get_jwt_identity()
    return User.query.get(user_id)


def update_search_vector(bookmark):
    """Update the search vector for a bookmark."""
    try:
        search_text = ' '.join(filter(None, [
            bookmark.title or '',
            bookmark.note_md or '',
            bookmark.og_title or '',
            bookmark.og_description or ''
        ]))
        
        if search_text.strip():
            db.session.execute(
                text("UPDATE bookmarks SET search_vector = to_tsvector('english', :text) WHERE id = :id"),
                {'text': search_text, 'id': bookmark.id}
            )
    except Exception as e:
        current_app.logger.error(f"Failed to update search vector: {str(e)}")


def enrich_bookmark_async(bookmark_id, url):
    """Asynchronously fetch and update bookmark metadata."""
    try:
        with current_app.app_context():
            bookmark = Bookmark.query.get(bookmark_id)
            if not bookmark:
                return
            
            metadata = fetch_metadata(url)
            
            # Update bookmark with fetched metadata
            if metadata['title'] and not bookmark.title:
                bookmark.title = metadata['title']
            
            if metadata['og_title']:
                bookmark.og_title = metadata['og_title']
            
            if metadata['og_description']:
                bookmark.og_description = metadata['og_description']
            
            if metadata['favicon_url']:
                bookmark.favicon_url = metadata['favicon_url']
            
            bookmark.updated_at = datetime.utcnow()
            
            db.session.commit()
            update_search_vector(bookmark)
            db.session.commit()
            
    except Exception as e:
        current_app.logger.error(f"Failed to enrich bookmark {bookmark_id}: {str(e)}")


# Bookmarks API
@api_bp.route('/bookmarks', methods=['GET'])
@jwt_required()
def get_bookmarks():
    """Get bookmarks with filtering, search, and pagination."""
    user = get_current_user()
    if not user:
        return jsonify({'error': 'User not found'}), 404
    
    # Query parameters
    query = request.args.get('query', '').strip()
    tag = request.args.get('tag', '').strip()
    category_id = request.args.get('category_id', type=int)
    include_archived = request.args.get('include_archived', 'false').lower() == 'true'
    page = request.args.get('page', 1, type=int)
    per_page = min(request.args.get('per_page', current_app.config['DEFAULT_PAGE_SIZE'], type=int), 
                   current_app.config['MAX_PAGE_SIZE'])
    sort = request.args.get('sort', 'created_at_desc')
    
    # Base query
    bookmarks_query = Bookmark.query.filter_by(user_id=user.id)
    
    # Filter by archive status
    if not include_archived:
        bookmarks_query = bookmarks_query.filter_by(is_archived=False)
    
    # Filter by category
    if category_id:
        bookmarks_query = bookmarks_query.filter_by(category_id=category_id)
    
    # Filter by tag
    if tag:
        bookmarks_query = bookmarks_query.join(Bookmark.tags).filter(Tag.name == tag)
    
    # Text search
    if query:
        # Use PostgreSQL full-text search
        search_query = text("search_vector @@ plainto_tsquery('english', :query)")
        bookmarks_query = bookmarks_query.filter(search_query.params(query=query))
    
    # Sorting
    if sort == 'created_at_desc':
        bookmarks_query = bookmarks_query.order_by(Bookmark.created_at.desc())
    elif sort == 'created_at_asc':
        bookmarks_query = bookmarks_query.order_by(Bookmark.created_at.asc())
    elif sort == 'title_asc':
        bookmarks_query = bookmarks_query.order_by(Bookmark.title.asc())
    elif sort == 'title_desc':
        bookmarks_query = bookmarks_query.order_by(Bookmark.title.desc())
    elif sort == 'updated_at_desc':
        bookmarks_query = bookmarks_query.order_by(Bookmark.updated_at.desc())
    
    # Pagination
    try:
        pagination = bookmarks_query.paginate(
            page=page, 
            per_page=per_page, 
            error_out=False
        )
        
        bookmarks = [bookmark.to_dict() for bookmark in pagination.items]
        
        return jsonify({
            'bookmarks': bookmarks,
            'pagination': {
                'page': page,
                'per_page': per_page,
                'total': pagination.total,
                'pages': pagination.pages,
                'has_next': pagination.has_next,
                'has_prev': pagination.has_prev
            }
        })
        
    except Exception as e:
        current_app.logger.error(f"Failed to get bookmarks: {str(e)}")
        return jsonify({'error': 'Failed to retrieve bookmarks'}), 500


@api_bp.route('/bookmarks', methods=['POST'])
@jwt_required()
def create_bookmark():
    """Create a new bookmark."""
    user = get_current_user()
    if not user:
        return jsonify({'error': 'User not found'}), 404
    
    data = request.get_json()
    if not data:
        return jsonify({'error': 'JSON data required'}), 400
    
    url = data.get('url', '').strip()
    title = data.get('title', '').strip()
    note_md = data.get('note_md', '').strip()
    category_id = data.get('category_id')
    tag_names = data.get('tags', [])
    
    # Validate URL
    normalized_url = normalize_url(url)
    if not normalized_url or not validate_url(normalized_url):
        return jsonify({'error': 'Invalid URL'}), 400
    
    # Check for duplicate URL
    existing = Bookmark.query.filter_by(user_id=user.id, url=normalized_url).first()
    if existing:
        return jsonify({'error': 'Bookmark already exists', 'bookmark_id': existing.id}), 409
    
    # Validate category
    if category_id:
        category = Category.query.filter_by(id=category_id, user_id=user.id).first()
        if not category:
            return jsonify({'error': 'Category not found'}), 404
    
    try:
        # Create bookmark
        bookmark = Bookmark(
            user_id=user.id,
            url=normalized_url,
            title=title or None,
            note_md=note_md or None,
            category_id=category_id
        )
        
        db.session.add(bookmark)
        db.session.flush()  # Get the ID
        
        # Handle tags
        if tag_names:
            for tag_name in tag_names:
                sanitized_name = sanitize_tag_name(tag_name)
                if sanitized_name:
                    tag = Tag.query.filter_by(user_id=user.id, name=sanitized_name).first()
                    if not tag:
                        tag = Tag(user_id=user.id, name=sanitized_name)
                        db.session.add(tag)
                    bookmark.tags.append(tag)
        
        db.session.commit()
        
        # Start background metadata enrichment if no title provided
        if not title:
            thread = threading.Thread(target=enrich_bookmark_async, args=(bookmark.id, normalized_url))
            thread.daemon = True
            thread.start()
        
        # Update search vector
        update_search_vector(bookmark)
        db.session.commit()
        
        return jsonify({
            'message': 'Bookmark created successfully',
            'bookmark': bookmark.to_dict()
        }), 201
        
    except Exception as e:
        db.session.rollback()
        current_app.logger.error(f"Failed to create bookmark: {str(e)}")
        return jsonify({'error': 'Failed to create bookmark'}), 500


@api_bp.route('/bookmarks/bulk', methods=['POST'])
@jwt_required()
def create_bookmarks_bulk():
    """Create multiple bookmarks from URL list."""
    user = get_current_user()
    if not user:
        return jsonify({'error': 'User not found'}), 404
    
    data = request.get_json()
    if not data:
        return jsonify({'error': 'JSON data required'}), 400
    
    urls_text = data.get('urls', '')
    category_id = data.get('category_id')
    tag_names = data.get('tags', [])
    
    # Parse URLs
    urls = parse_bulk_urls(urls_text)
    if not urls:
        return jsonify({'error': 'No valid URLs provided'}), 400
    
    if len(urls) > 100:  # Limit bulk operations
        return jsonify({'error': 'Too many URLs (max 100)'}), 400
    
    # Validate category
    if category_id:
        category = Category.query.filter_by(id=category_id, user_id=user.id).first()
        if not category:
            return jsonify({'error': 'Category not found'}), 404
    
    try:
        created_bookmarks = []
        skipped_urls = []
        
        for url in urls:
            # Check for duplicate
            existing = Bookmark.query.filter_by(user_id=user.id, url=url).first()
            if existing:
                skipped_urls.append(url)
                continue
            
            # Create bookmark
            bookmark = Bookmark(
                user_id=user.id,
                url=url,
                category_id=category_id
            )
            
            db.session.add(bookmark)
            db.session.flush()
            
            # Handle tags
            if tag_names:
                for tag_name in tag_names:
                    sanitized_name = sanitize_tag_name(tag_name)
                    if sanitized_name:
                        tag = Tag.query.filter_by(user_id=user.id, name=sanitized_name).first()
                        if not tag:
                            tag = Tag(user_id=user.id, name=sanitized_name)
                            db.session.add(tag)
                        bookmark.tags.append(tag)
            
            created_bookmarks.append(bookmark)
        
        db.session.commit()
        
        # Start background enrichment for all created bookmarks
        for bookmark in created_bookmarks:
            thread = threading.Thread(target=enrich_bookmark_async, args=(bookmark.id, bookmark.url))
            thread.daemon = True
            thread.start()
        
        return jsonify({
            'message': f'Created {len(created_bookmarks)} bookmarks',
            'created_count': len(created_bookmarks),
            'skipped_count': len(skipped_urls),
            'bookmarks': [bookmark.to_dict() for bookmark in created_bookmarks]
        }), 201
        
    except Exception as e:
        db.session.rollback()
        current_app.logger.error(f"Failed to create bulk bookmarks: {str(e)}")
        return jsonify({'error': 'Failed to create bookmarks'}), 500


@api_bp.route('/bookmarks/<int:bookmark_id>', methods=['GET'])
@jwt_required()
def get_bookmark(bookmark_id):
    """Get a specific bookmark."""
    user = get_current_user()
    if not user:
        return jsonify({'error': 'User not found'}), 404
    
    bookmark = Bookmark.query.filter_by(id=bookmark_id, user_id=user.id).first()
    if not bookmark:
        return jsonify({'error': 'Bookmark not found'}), 404
    
    return jsonify({'bookmark': bookmark.to_dict()})


@api_bp.route('/bookmarks/<int:bookmark_id>', methods=['PATCH'])
@jwt_required()
def update_bookmark(bookmark_id):
    """Update a bookmark."""
    user = get_current_user()
    if not user:
        return jsonify({'error': 'User not found'}), 404
    
    bookmark = Bookmark.query.filter_by(id=bookmark_id, user_id=user.id).first()
    if not bookmark:
        return jsonify({'error': 'Bookmark not found'}), 404
    
    data = request.get_json()
    if not data:
        return jsonify({'error': 'JSON data required'}), 400
    
    try:
        # Update fields
        if 'title' in data:
            bookmark.title = data['title'].strip() or None
        
        if 'note_md' in data:
            bookmark.note_md = data['note_md'].strip() or None
        
        if 'category_id' in data:
            category_id = data['category_id']
            if category_id:
                category = Category.query.filter_by(id=category_id, user_id=user.id).first()
                if not category:
                    return jsonify({'error': 'Category not found'}), 404
            bookmark.category_id = category_id
        
        if 'is_archived' in data:
            bookmark.is_archived = bool(data['is_archived'])
        
        # Update tags
        if 'tags' in data:
            bookmark.tags.clear()
            for tag_name in data['tags']:
                sanitized_name = sanitize_tag_name(tag_name)
                if sanitized_name:
                    tag = Tag.query.filter_by(user_id=user.id, name=sanitized_name).first()
                    if not tag:
                        tag = Tag(user_id=user.id, name=sanitized_name)
                        db.session.add(tag)
                    bookmark.tags.append(tag)
        
        bookmark.updated_at = datetime.utcnow()
        db.session.commit()
        
        # Update search vector
        update_search_vector(bookmark)
        db.session.commit()
        
        return jsonify({
            'message': 'Bookmark updated successfully',
            'bookmark': bookmark.to_dict()
        })
        
    except Exception as e:
        db.session.rollback()
        current_app.logger.error(f"Failed to update bookmark: {str(e)}")
        return jsonify({'error': 'Failed to update bookmark'}), 500


@api_bp.route('/bookmarks/<int:bookmark_id>', methods=['DELETE'])
@jwt_required()
def delete_bookmark(bookmark_id):
    """Delete a bookmark."""
    user = get_current_user()
    if not user:
        return jsonify({'error': 'User not found'}), 404
    
    bookmark = Bookmark.query.filter_by(id=bookmark_id, user_id=user.id).first()
    if not bookmark:
        return jsonify({'error': 'Bookmark not found'}), 404
    
    try:
        db.session.delete(bookmark)
        db.session.commit()
        
        return jsonify({'message': 'Bookmark deleted successfully'})
        
    except Exception as e:
        db.session.rollback()
        current_app.logger.error(f"Failed to delete bookmark: {str(e)}")
        return jsonify({'error': 'Failed to delete bookmark'}), 500


@api_bp.route('/bookmarks/<int:bookmark_id>/refresh', methods=['POST'])
@jwt_required()
def refresh_bookmark_metadata(bookmark_id):
    """Manually refresh bookmark metadata."""
    user = get_current_user()
    if not user:
        return jsonify({'error': 'User not found'}), 404
    
    bookmark = Bookmark.query.filter_by(id=bookmark_id, user_id=user.id).first()
    if not bookmark:
        return jsonify({'error': 'Bookmark not found'}), 404
    
    try:
        metadata = fetch_metadata(bookmark.url)
        
        # Update bookmark with fetched metadata
        if metadata['title']:
            bookmark.title = metadata['title']
        
        if metadata['og_title']:
            bookmark.og_title = metadata['og_title']
        
        if metadata['og_description']:
            bookmark.og_description = metadata['og_description']
        
        if metadata['favicon_url']:
            bookmark.favicon_url = metadata['favicon_url']
        
        bookmark.updated_at = datetime.utcnow()
        db.session.commit()
        
        # Update search vector
        update_search_vector(bookmark)
        db.session.commit()
        
        return jsonify({
            'message': 'Metadata refreshed successfully',
            'bookmark': bookmark.to_dict()
        })
        
    except Exception as e:
        db.session.rollback()
        current_app.logger.error(f"Failed to refresh metadata: {str(e)}")
        return jsonify({'error': 'Failed to refresh metadata'}), 500


# Categories API
@api_bp.route('/categories/tree', methods=['GET'])
@jwt_required()
def get_categories_tree():
    """Get categories in tree structure."""
    user = get_current_user()
    if not user:
        return jsonify({'error': 'User not found'}), 404
    
    try:
        # Get root categories (no parent)
        root_categories = Category.query.filter_by(user_id=user.id, parent_id=None).all()
        
        categories_tree = [cat.to_dict(include_children=True) for cat in root_categories]
        
        return jsonify({'categories': categories_tree})
        
    except Exception as e:
        current_app.logger.error(f"Failed to get categories: {str(e)}")
        return jsonify({'error': 'Failed to retrieve categories'}), 500


@api_bp.route('/categories', methods=['POST'])
@jwt_required()
def create_category():
    """Create a new category."""
    user = get_current_user()
    if not user:
        return jsonify({'error': 'User not found'}), 404
    
    data = request.get_json()
    if not data:
        return jsonify({'error': 'JSON data required'}), 400
    
    name = data.get('name', '').strip()
    parent_id = data.get('parent_id')
    
    if not name:
        return jsonify({'error': 'Category name required'}), 400
    
    if len(name) > 120:
        return jsonify({'error': 'Category name too long'}), 400
    
    # Check if category name already exists for this user
    existing = Category.query.filter_by(user_id=user.id, name=name).first()
    if existing:
        return jsonify({'error': 'Category name already exists'}), 409
    
    # Validate parent category
    if parent_id:
        parent = Category.query.filter_by(id=parent_id, user_id=user.id).first()
        if not parent:
            return jsonify({'error': 'Parent category not found'}), 404
    
    try:
        category = Category(
            user_id=user.id,
            name=name,
            parent_id=parent_id
        )
        
        db.session.add(category)
        db.session.commit()
        
        return jsonify({
            'message': 'Category created successfully',
            'category': category.to_dict()
        }), 201
        
    except Exception as e:
        db.session.rollback()
        current_app.logger.error(f"Failed to create category: {str(e)}")
        return jsonify({'error': 'Failed to create category'}), 500


@api_bp.route('/categories/<int:category_id>', methods=['PATCH'])
@jwt_required()
def update_category(category_id):
    """Update a category."""
    user = get_current_user()
    if not user:
        return jsonify({'error': 'User not found'}), 404
    
    category = Category.query.filter_by(id=category_id, user_id=user.id).first()
    if not category:
        return jsonify({'error': 'Category not found'}), 404
    
    data = request.get_json()
    if not data:
        return jsonify({'error': 'JSON data required'}), 400
    
    try:
        if 'name' in data:
            name = data['name'].strip()
            if not name:
                return jsonify({'error': 'Category name required'}), 400
            
            # Check for duplicate name
            existing = Category.query.filter(
                Category.user_id == user.id,
                Category.name == name,
                Category.id != category_id
            ).first()
            if existing:
                return jsonify({'error': 'Category name already exists'}), 409
            
            category.name = name
        
        if 'parent_id' in data:
            parent_id = data['parent_id']
            if parent_id:
                # Validate parent and prevent circular references
                parent = Category.query.filter_by(id=parent_id, user_id=user.id).first()
                if not parent:
                    return jsonify({'error': 'Parent category not found'}), 404
                
                # Check for circular reference
                current_parent = parent
                while current_parent:
                    if current_parent.id == category_id:
                        return jsonify({'error': 'Circular reference not allowed'}), 400
                    current_parent = current_parent.parent
            
            category.parent_id = parent_id
        
        db.session.commit()
        
        return jsonify({
            'message': 'Category updated successfully',
            'category': category.to_dict()
        })
        
    except Exception as e:
        db.session.rollback()
        current_app.logger.error(f"Failed to update category: {str(e)}")
        return jsonify({'error': 'Failed to update category'}), 500


@api_bp.route('/categories/<int:category_id>', methods=['DELETE'])
@jwt_required()
def delete_category(category_id):
    """Delete a category and move bookmarks to parent or uncategorized."""
    user = get_current_user()
    if not user:
        return jsonify({'error': 'User not found'}), 404
    
    category = Category.query.filter_by(id=category_id, user_id=user.id).first()
    if not category:
        return jsonify({'error': 'Category not found'}), 404
    
    try:
        # Move bookmarks to parent category or uncategorized
        bookmarks = Bookmark.query.filter_by(category_id=category_id).all()
        for bookmark in bookmarks:
            bookmark.category_id = category.parent_id
        
        # Move child categories to parent
        child_categories = Category.query.filter_by(parent_id=category_id).all()
        for child in child_categories:
            child.parent_id = category.parent_id
        
        db.session.delete(category)
        db.session.commit()
        
        return jsonify({'message': 'Category deleted successfully'})
        
    except Exception as e:
        db.session.rollback()
        current_app.logger.error(f"Failed to delete category: {str(e)}")
        return jsonify({'error': 'Failed to delete category'}), 500


# Tags API
@api_bp.route('/tags', methods=['GET'])
@jwt_required()
def get_tags():
    """Get all user tags."""
    user = get_current_user()
    if not user:
        return jsonify({'error': 'User not found'}), 404
    
    try:
        tags = Tag.query.filter_by(user_id=user.id).order_by(Tag.name).all()
        
        return jsonify({
            'tags': [tag.to_dict() for tag in tags]
        })
        
    except Exception as e:
        current_app.logger.error(f"Failed to get tags: {str(e)}")
        return jsonify({'error': 'Failed to retrieve tags'}), 500


@api_bp.route('/tags', methods=['POST'])
@jwt_required()
def create_tag():
    """Create a new tag."""
    user = get_current_user()
    if not user:
        return jsonify({'error': 'User not found'}), 404
    
    data = request.get_json()
    if not data:
        return jsonify({'error': 'JSON data required'}), 400
    
    name = data.get('name', '').strip()
    
    if not name:
        return jsonify({'error': 'Tag name required'}), 400
    
    sanitized_name = sanitize_tag_name(name)
    if not sanitized_name:
        return jsonify({'error': 'Invalid tag name'}), 400
    
    # Check if tag already exists
    existing = Tag.query.filter_by(user_id=user.id, name=sanitized_name).first()
    if existing:
        return jsonify({'error': 'Tag already exists', 'tag': existing.to_dict()}), 409
    
    try:
        tag = Tag(
            user_id=user.id,
            name=sanitized_name
        )
        
        db.session.add(tag)
        db.session.commit()
        
        return jsonify({
            'message': 'Tag created successfully',
            'tag': tag.to_dict()
        }), 201
        
    except Exception as e:
        db.session.rollback()
        current_app.logger.error(f"Failed to create tag: {str(e)}")
        return jsonify({'error': 'Failed to create tag'}), 500


@api_bp.route('/tags/<int:tag_id>', methods=['DELETE'])
@jwt_required()
def delete_tag(tag_id):
    """Delete a tag."""
    user = get_current_user()
    if not user:
        return jsonify({'error': 'User not found'}), 404
    
    tag = Tag.query.filter_by(id=tag_id, user_id=user.id).first()
    if not tag:
        return jsonify({'error': 'Tag not found'}), 404
    
    try:
        db.session.delete(tag)
        db.session.commit()
        
        return jsonify({'message': 'Tag deleted successfully'})
        
    except Exception as e:
        db.session.rollback()
        current_app.logger.error(f"Failed to delete tag: {str(e)}")
        return jsonify({'error': 'Failed to delete tag'}), 500


# Redirect endpoint (outside JWT requirement for public access)
@api_bp.route('/r/<int:bookmark_id>')
def redirect_bookmark(bookmark_id):
    """Redirect to bookmark URL."""
    try:
        bookmark = Bookmark.query.get(bookmark_id)
        if not bookmark:
            return jsonify({'error': 'Bookmark not found'}), 404
        
        # Optional: Track click/visit here
        # bookmark.visit_count += 1
        # bookmark.last_visited = datetime.utcnow()
        # db.session.commit()
        
        return redirect(bookmark.url, code=302)
        
    except Exception as e:
        current_app.logger.error(f"Failed to redirect bookmark: {str(e)}")
        return jsonify({'error': 'Redirect failed'}), 500
