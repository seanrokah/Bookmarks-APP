from flask import Blueprint, render_template, request, redirect, url_for, flash, session, jsonify
from flask_jwt_extended import jwt_required, get_jwt_identity, verify_jwt_in_request
from models import db, User, Bookmark, Category, Tag
from sqlalchemy import func, text
from datetime import datetime
import json

main_bp = Blueprint('main', __name__)


def get_current_user():
    """Get current authenticated user from session or JWT."""
    try:
        verify_jwt_in_request(optional=True)
        user_id = get_jwt_identity()
        if user_id:
            return User.query.get(user_id)
    except:
        pass
    
    # Fallback to session-based auth for web interface
    user_id = session.get('user_id')
    if user_id:
        return User.query.get(user_id)
    
    return None


@main_bp.route('/')
def index():
    """Home page - redirect to dashboard if authenticated, otherwise show landing."""
    user = get_current_user()
    if user:
        return redirect(url_for('main.dashboard'))
    return render_template('landing.html')


@main_bp.route('/login')
def login_page():
    """Login page."""
    user = get_current_user()
    if user:
        return redirect(url_for('main.dashboard'))
    return render_template('login.html')


@main_bp.route('/register')
def register_page():
    """Registration page."""
    user = get_current_user()
    if user:
        return redirect(url_for('main.dashboard'))
    return render_template('register.html')


@main_bp.route('/dashboard')
def dashboard():
    """Main dashboard."""
    user = get_current_user()
    if not user:
        return redirect(url_for('main.login_page'))
    
    # Get dashboard statistics
    try:
        stats = {
            'total_bookmarks': Bookmark.query.filter_by(user_id=user.id, is_archived=False).count(),
            'total_categories': Category.query.filter_by(user_id=user.id).count(),
            'total_tags': Tag.query.filter_by(user_id=user.id).count(),
            'archived_bookmarks': Bookmark.query.filter_by(user_id=user.id, is_archived=True).count()
        }
        
        # Recent bookmarks
        recent_bookmarks = Bookmark.query.filter_by(
            user_id=user.id, 
            is_archived=False
        ).order_by(Bookmark.created_at.desc()).limit(10).all()
        
        # Categories with bookmark counts
        categories = Category.query.filter_by(user_id=user.id).all()
        
        # Popular tags (by bookmark count)
        popular_tags = db.session.query(
            Tag.name,
            func.count(Tag.id).label('count')
        ).join(Tag.bookmarks).filter(
            Tag.user_id == user.id
        ).group_by(Tag.name).order_by(
            func.count(Tag.id).desc()
        ).limit(20).all()
        
        return render_template('dashboard.html', 
                             user=user,
                             stats=stats,
                             recent_bookmarks=recent_bookmarks,
                             categories=categories,
                             popular_tags=popular_tags)
        
    except Exception as e:
        flash('Error loading dashboard', 'error')
        return render_template('dashboard.html', user=user, stats={}, 
                             recent_bookmarks=[], categories=[], popular_tags=[])


@main_bp.route('/bookmarks')
def bookmarks():
    """Bookmarks page with search and filtering."""
    user = get_current_user()
    if not user:
        return redirect(url_for('main.login_page'))
    
    # Get filter parameters
    query = request.args.get('query', '').strip()
    category_id = request.args.get('category_id', type=int)
    tag = request.args.get('tag', '').strip()
    include_archived = request.args.get('include_archived', 'false').lower() == 'true'
    
    # Get categories for filter dropdown
    categories = Category.query.filter_by(user_id=user.id).order_by(Category.name).all()
    
    # Get tags for filter dropdown
    tags = Tag.query.filter_by(user_id=user.id).order_by(Tag.name).all()
    
    return render_template('bookmarks.html',
                         user=user,
                         categories=categories,
                         tags=tags,
                         current_query=query,
                         current_category_id=category_id,
                         current_tag=tag,
                         include_archived=include_archived)


@main_bp.route('/bookmarks/add')
def add_bookmark():
    """Add bookmark page."""
    user = get_current_user()
    if not user:
        return redirect(url_for('main.login_page'))
    
    categories = Category.query.filter_by(user_id=user.id).order_by(Category.name).all()
    tags = Tag.query.filter_by(user_id=user.id).order_by(Tag.name).all()
    
    return render_template('add_bookmark.html',
                         user=user,
                         categories=categories,
                         tags=tags)


@main_bp.route('/bookmarks/bulk')
def bulk_add():
    """Bulk add bookmarks page."""
    user = get_current_user()
    if not user:
        return redirect(url_for('main.login_page'))
    
    categories = Category.query.filter_by(user_id=user.id).order_by(Category.name).all()
    tags = Tag.query.filter_by(user_id=user.id).order_by(Tag.name).all()
    
    return render_template('bulk_add.html',
                         user=user,
                         categories=categories,
                         tags=tags)


@main_bp.route('/categories')
def categories():
    """Categories management page."""
    user = get_current_user()
    if not user:
        return redirect(url_for('main.login_page'))
    
    # Get categories with bookmark counts
    categories = Category.query.filter_by(user_id=user.id).all()
    
    return render_template('categories.html',
                         user=user,
                         categories=categories)


@main_bp.route('/tags')
def tags():
    """Tags management page."""
    user = get_current_user()
    if not user:
        return redirect(url_for('main.login_page'))
    
    # Get tags with bookmark counts
    tags_with_counts = db.session.query(
        Tag,
        func.count(Tag.id).label('bookmark_count')
    ).outerjoin(Tag.bookmarks).filter(
        Tag.user_id == user.id
    ).group_by(Tag.id).order_by(Tag.name).all()
    
    return render_template('tags.html',
                         user=user,
                         tags_with_counts=tags_with_counts)


@main_bp.route('/search')
def search():
    """Advanced search page."""
    user = get_current_user()
    if not user:
        return redirect(url_for('main.login_page'))
    
    categories = Category.query.filter_by(user_id=user.id).order_by(Category.name).all()
    tags = Tag.query.filter_by(user_id=user.id).order_by(Tag.name).all()
    
    return render_template('search.html',
                         user=user,
                         categories=categories,
                         tags=tags)


@main_bp.route('/settings')
def settings():
    """User settings page."""
    user = get_current_user()
    if not user:
        return redirect(url_for('main.login_page'))
    
    return render_template('settings.html', user=user)


@main_bp.route('/logout')
def logout():
    """Logout user."""
    session.clear()
    flash('You have been logged out', 'info')
    return redirect(url_for('main.index'))


# HTMX endpoints for dynamic content
@main_bp.route('/htmx/bookmark-card/<int:bookmark_id>')
def bookmark_card(bookmark_id):
    """Return bookmark card HTML for HTMX."""
    user = get_current_user()
    if not user:
        return '', 401
    
    bookmark = Bookmark.query.filter_by(id=bookmark_id, user_id=user.id).first()
    if not bookmark:
        return '', 404
    
    return render_template('components/bookmark_card.html', bookmark=bookmark)


@main_bp.route('/htmx/category-tree')
def category_tree():
    """Return category tree HTML for HTMX."""
    user = get_current_user()
    if not user:
        return '', 401
    
    categories = Category.query.filter_by(user_id=user.id, parent_id=None).all()
    return render_template('components/category_tree.html', categories=categories)


# API endpoint for web login (session-based)
@main_bp.route('/web-login', methods=['POST'])
def web_login():
    """Handle web-based login (creates session)."""
    data = request.get_json()
    email = data.get('email', '').strip().lower()
    password = data.get('password', '')
    
    if not email or not password:
        return jsonify({'error': 'Email and password required'}), 400
    
    user = User.query.filter_by(email=email).first()
    
    if not user or not user.check_password(password):
        return jsonify({'error': 'Invalid email or password'}), 401
    
    # Create session
    session['user_id'] = user.id
    session.permanent = True
    
    return jsonify({
        'message': 'Login successful',
        'redirect': url_for('main.dashboard')
    })


@main_bp.route('/web-register', methods=['POST'])
def web_register():
    """Handle web-based registration (creates session)."""
    from auth import validate_email, validate_password
    
    data = request.get_json()
    email = data.get('email', '').strip().lower()
    password = data.get('password', '')
    display_name = data.get('display_name', '').strip()
    
    # Validate input
    if not validate_email(email):
        return jsonify({'error': 'Invalid email address'}), 400
    
    is_valid, error_msg = validate_password(password)
    if not is_valid:
        return jsonify({'error': error_msg}), 400
    
    # Check if user already exists
    if User.query.filter_by(email=email).first():
        return jsonify({'error': 'Email already registered'}), 409
    
    try:
        # Create new user
        user = User(
            email=email,
            display_name=display_name or None
        )
        user.set_password(password)
        
        db.session.add(user)
        db.session.commit()
        
        # Create session
        session['user_id'] = user.id
        session.permanent = True
        
        return jsonify({
            'message': 'Registration successful',
            'redirect': url_for('main.dashboard')
        })
        
    except Exception as e:
        db.session.rollback()
        return jsonify({'error': 'Registration failed'}), 500


# Session-based API endpoints for web interface
@main_bp.route('/web-api/bookmarks', methods=['POST'])
def web_create_bookmark():
    """Create a new bookmark (session-based auth)."""
    user = get_current_user()
    if not user:
        return jsonify({'error': 'Authentication required'}), 401
    
    from utils import normalize_url, validate_url, sanitize_tag_name
    
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
        
        return jsonify({
            'message': 'Bookmark created successfully',
            'bookmark': bookmark.to_dict()
        }), 201
        
    except Exception as e:
        db.session.rollback()
        return jsonify({'error': 'Failed to create bookmark'}), 500


@main_bp.route('/web-api/categories', methods=['POST'])
def web_create_category():
    """Create a new category (session-based auth)."""
    user = get_current_user()
    if not user:
        return jsonify({'error': 'Authentication required'}), 401
    
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
        return jsonify({'error': 'Failed to create category'}), 500


@main_bp.route('/web-api/categories/<int:category_id>', methods=['PATCH'])
def web_update_category(category_id):
    """Update a category (session-based auth)."""
    user = get_current_user()
    if not user:
        return jsonify({'error': 'Authentication required'}), 401
    
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
        return jsonify({'error': 'Failed to update category'}), 500


@main_bp.route('/web-api/categories/<int:category_id>', methods=['DELETE'])
def web_delete_category(category_id):
    """Delete a category (session-based auth)."""
    user = get_current_user()
    if not user:
        return jsonify({'error': 'Authentication required'}), 401
    
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
        return jsonify({'error': 'Failed to delete category'}), 500


@main_bp.route('/web-api/bookmarks/bulk', methods=['POST'])
def web_create_bookmarks_bulk():
    """Create multiple bookmarks from URL list (session-based auth)."""
    user = get_current_user()
    if not user:
        return jsonify({'error': 'Authentication required'}), 401
    
    from utils import parse_bulk_urls, sanitize_tag_name
    
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
        
        return jsonify({
            'message': f'Created {len(created_bookmarks)} bookmarks',
            'created_count': len(created_bookmarks),
            'skipped_count': len(skipped_urls),
            'bookmarks': [bookmark.to_dict() for bookmark in created_bookmarks]
        }), 201
        
    except Exception as e:
        db.session.rollback()
        return jsonify({'error': 'Failed to create bookmarks'}), 500


@main_bp.route('/web-api/tags', methods=['POST'])
def web_create_tag():
    """Create a new tag (session-based auth)."""
    user = get_current_user()
    if not user:
        return jsonify({'error': 'Authentication required'}), 401
    
    from utils import sanitize_tag_name
    
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
        return jsonify({'error': 'Failed to create tag'}), 500


@main_bp.route('/web-api/tags/<int:tag_id>', methods=['DELETE'])
def web_delete_tag(tag_id):
    """Delete a tag (session-based auth)."""
    user = get_current_user()
    if not user:
        return jsonify({'error': 'Authentication required'}), 401
    
    tag = Tag.query.filter_by(id=tag_id, user_id=user.id).first()
    if not tag:
        return jsonify({'error': 'Tag not found'}), 404
    
    try:
        db.session.delete(tag)
        db.session.commit()
        
        return jsonify({'message': 'Tag deleted successfully'})
        
    except Exception as e:
        db.session.rollback()
        return jsonify({'error': 'Failed to delete tag'}), 500


@main_bp.route('/web-api/bookmarks', methods=['GET'])
def web_get_bookmarks():
    """Get bookmarks with filtering, search, and pagination (session-based auth)."""
    user = get_current_user()
    if not user:
        return jsonify({'error': 'Authentication required'}), 401
    
    # Query parameters
    query = request.args.get('query', '').strip()
    tag = request.args.get('tag', '').strip()
    category_id = request.args.get('category_id', type=int)
    include_archived = request.args.get('include_archived', 'false').lower() == 'true'
    page = request.args.get('page', 1, type=int)
    per_page = min(request.args.get('per_page', 20, type=int), 100)
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
        return jsonify({'error': 'Failed to retrieve bookmarks'}), 500


@main_bp.route('/web-api/auth/change-password', methods=['POST'])
def web_change_password():
    """Change user password (session-based auth)."""
    user = get_current_user()
    if not user:
        return jsonify({'error': 'Authentication required'}), 401
    
    from auth import validate_password
    
    data = request.get_json()
    if not data:
        return jsonify({'error': 'JSON data required'}), 400
    
    current_password = data.get('current_password', '')
    new_password = data.get('new_password', '')
    
    if not current_password or not new_password:
        return jsonify({'error': 'Current and new password required'}), 400
    
    # Validate new password
    is_valid, error_msg = validate_password(new_password)
    if not is_valid:
        return jsonify({'error': error_msg}), 400
    
    try:
        if not user.check_password(current_password):
            return jsonify({'error': 'Current password is incorrect'}), 401
        
        user.set_password(new_password)
        db.session.commit()
        
        return jsonify({'message': 'Password changed successfully'})
        
    except Exception as e:
        db.session.rollback()
        return jsonify({'error': 'Failed to change password'}), 500


@main_bp.route('/web-api/bookmarks/<int:bookmark_id>', methods=['GET'])
def web_get_bookmark(bookmark_id):
    """Get a specific bookmark (session-based auth)."""
    user = get_current_user()
    if not user:
        return jsonify({'error': 'Authentication required'}), 401
    
    bookmark = Bookmark.query.filter_by(id=bookmark_id, user_id=user.id).first()
    if not bookmark:
        return jsonify({'error': 'Bookmark not found'}), 404
    
    return jsonify({'bookmark': bookmark.to_dict()})


@main_bp.route('/web-api/bookmarks/<int:bookmark_id>', methods=['PATCH'])
def web_update_bookmark(bookmark_id):
    """Update a bookmark (session-based auth)."""
    user = get_current_user()
    if not user:
        return jsonify({'error': 'Authentication required'}), 401
    
    bookmark = Bookmark.query.filter_by(id=bookmark_id, user_id=user.id).first()
    if not bookmark:
        return jsonify({'error': 'Bookmark not found'}), 404
    
    data = request.get_json()
    if not data:
        return jsonify({'error': 'JSON data required'}), 400
    
    from utils import sanitize_tag_name
    
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
        
        return jsonify({
            'message': 'Bookmark updated successfully',
            'bookmark': bookmark.to_dict()
        })
        
    except Exception as e:
        db.session.rollback()
        return jsonify({'error': 'Failed to update bookmark'}), 500


@main_bp.route('/web-api/bookmarks/<int:bookmark_id>', methods=['DELETE'])
def web_delete_bookmark(bookmark_id):
    """Delete a bookmark (session-based auth)."""
    user = get_current_user()
    if not user:
        return jsonify({'error': 'Authentication required'}), 401
    
    bookmark = Bookmark.query.filter_by(id=bookmark_id, user_id=user.id).first()
    if not bookmark:
        return jsonify({'error': 'Bookmark not found'}), 404
    
    try:
        db.session.delete(bookmark)
        db.session.commit()
        
        return jsonify({'message': 'Bookmark deleted successfully'})
        
    except Exception as e:
        db.session.rollback()
        return jsonify({'error': 'Failed to delete bookmark'}), 500
