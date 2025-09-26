import re
import requests
from urllib.parse import urlparse, urlunparse
from bs4 import BeautifulSoup
import validators
from flask import current_app


def normalize_url(url):
    """Normalize and clean URL."""
    if not url:
        return None
    
    # Add scheme if missing
    if not url.startswith(('http://', 'https://')):
        url = 'https://' + url
    
    try:
        parsed = urlparse(url)
        
        # Convert hostname to lowercase
        hostname = parsed.hostname
        if hostname:
            hostname = hostname.lower()
        
        # Remove common UTM parameters
        utm_params = ['utm_source', 'utm_medium', 'utm_campaign', 'utm_term', 'utm_content']
        if parsed.query:
            query_params = []
            for param in parsed.query.split('&'):
                if '=' in param:
                    key, value = param.split('=', 1)
                    if key not in utm_params:
                        query_params.append(param)
                else:
                    if param not in utm_params:
                        query_params.append(param)
            query = '&'.join(query_params)
        else:
            query = ''
        
        # Reconstruct URL
        normalized = urlunparse((
            parsed.scheme,
            hostname + (f':{parsed.port}' if parsed.port and parsed.port not in [80, 443] else ''),
            parsed.path,
            parsed.params,
            query,
            ''  # Remove fragment
        ))
        
        return normalized
        
    except Exception:
        return url


def validate_url(url):
    """Validate URL format and scheme."""
    if not url:
        return False
    
    return validators.url(url) and url.startswith(('http://', 'https://'))


def fetch_metadata(url, timeout=None):
    """Fetch page metadata (title, OG data, favicon)."""
    if timeout is None:
        timeout = current_app.config.get('METADATA_FETCH_TIMEOUT', 10)
    
    metadata = {
        'title': None,
        'og_title': None,
        'og_description': None,
        'favicon_url': None
    }
    
    try:
        headers = {
            'User-Agent': 'Mozilla/5.0 (compatible; BookmarkMaster/1.0)',
            'Accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8',
            'Accept-Language': 'en-US,en;q=0.5',
            'Accept-Encoding': 'gzip, deflate',
            'Connection': 'keep-alive',
        }
        
        response = requests.get(
            url, 
            headers=headers, 
            timeout=timeout,
            allow_redirects=True,
            stream=True
        )
        
        # Check content size
        content_length = response.headers.get('content-length')
        max_size = current_app.config.get('MAX_CONTENT_SIZE', 1024 * 1024)
        
        if content_length and int(content_length) > max_size:
            current_app.logger.warning(f"Content too large for {url}: {content_length} bytes")
            return metadata
        
        # Only process HTML content
        content_type = response.headers.get('content-type', '').lower()
        if 'text/html' not in content_type:
            return metadata
        
        response.raise_for_status()
        
        # Read content with size limit
        content = response.content[:max_size]
        soup = BeautifulSoup(content, 'html.parser')
        
        # Extract title
        title_tag = soup.find('title')
        if title_tag:
            metadata['title'] = title_tag.get_text().strip()[:512]
        
        # Extract Open Graph data
        og_title = soup.find('meta', property='og:title')
        if og_title:
            metadata['og_title'] = og_title.get('content', '').strip()[:512]
        
        og_description = soup.find('meta', property='og:description')
        if og_description:
            metadata['og_description'] = og_description.get('content', '').strip()[:1024]
        
        # Try to find favicon
        favicon_candidates = []
        
        # Look for favicon link tags
        for link in soup.find_all('link', rel=True):
            rel = ' '.join(link['rel']).lower()
            if any(favicon_type in rel for favicon_type in ['icon', 'shortcut icon', 'apple-touch-icon']):
                href = link.get('href')
                if href:
                    favicon_candidates.append(href)
        
        # Add default favicon location
        parsed_url = urlparse(url)
        default_favicon = f"{parsed_url.scheme}://{parsed_url.netloc}/favicon.ico"
        favicon_candidates.append(default_favicon)
        
        # Try to resolve relative URLs and pick the first valid one
        for favicon_href in favicon_candidates:
            try:
                if favicon_href.startswith('//'):
                    favicon_url = f"{parsed_url.scheme}:{favicon_href}"
                elif favicon_href.startswith('/'):
                    favicon_url = f"{parsed_url.scheme}://{parsed_url.netloc}{favicon_href}"
                elif not favicon_href.startswith(('http://', 'https://')):
                    favicon_url = f"{parsed_url.scheme}://{parsed_url.netloc}/{favicon_href}"
                else:
                    favicon_url = favicon_href
                
                # Quick check if favicon exists (HEAD request)
                favicon_response = requests.head(favicon_url, timeout=5, allow_redirects=True)
                if favicon_response.status_code == 200:
                    metadata['favicon_url'] = favicon_url
                    break
                    
            except Exception:
                continue
        
        return metadata
        
    except Exception as e:
        current_app.logger.warning(f"Failed to fetch metadata for {url}: {str(e)}")
        return metadata


def sanitize_tag_name(name):
    """Sanitize and normalize tag name."""
    if not name:
        return None
    
    # Convert to lowercase, strip whitespace
    name = name.strip().lower()
    
    # Remove special characters, keep only alphanumeric, hyphens, underscores
    name = re.sub(r'[^a-z0-9\-_\s]', '', name)
    
    # Replace spaces with hyphens
    name = re.sub(r'\s+', '-', name)
    
    # Remove multiple consecutive hyphens
    name = re.sub(r'-+', '-', name)
    
    # Remove leading/trailing hyphens
    name = name.strip('-')
    
    # Limit length
    if len(name) > 64:
        name = name[:64].rstrip('-')
    
    return name if name else None


def parse_bulk_urls(text):
    """Parse bulk URL input (comma or newline separated)."""
    if not text:
        return []
    
    # Split by comma or newline
    urls = []
    for line in text.split('\n'):
        for url in line.split(','):
            url = url.strip()
            if url:
                normalized = normalize_url(url)
                if normalized and validate_url(normalized):
                    urls.append(normalized)
    
    return list(set(urls))  # Remove duplicates
