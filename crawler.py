"""
Web crawler module for discovering endpoints and input points.
"""
import re
import requests
from urllib.parse import urljoin, urlparse, parse_qs, urlencode
from bs4 import BeautifulSoup
from typing import List, Dict, Set, Optional
from collections import deque
import time


class WebCrawler:
    """Crawls web applications to discover endpoints and input points."""
    
    def __init__(self, base_url: str, max_depth: int = 3, delay: float = 0.5):
        """
        Initialize the web crawler.
        
        Args:
            base_url: Base URL to start crawling from
            max_depth: Maximum depth to crawl
            delay: Delay between requests (seconds)
        """
        self.base_url = base_url.rstrip('/')
        self.max_depth = max_depth
        self.delay = delay
        self.visited_urls: Set[str] = set()
        self.discovered_endpoints: List[Dict] = []
        self.session = requests.Session()
        self.session.headers.update({
            'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36'
        })
    
    def is_valid_url(self, url: str) -> bool:
        """Check if URL is valid and within scope."""
        try:
            parsed = urlparse(url)
            base_parsed = urlparse(self.base_url)
            
            # Only crawl same domain
            if parsed.netloc and parsed.netloc != base_parsed.netloc:
                return False
            
            # Skip non-HTTP(S) protocols
            if parsed.scheme not in ['http', 'https', '']:
                return False
            
            # Skip common non-HTML extensions
            skip_extensions = ['.pdf', '.jpg', '.jpeg', '.png', '.gif', '.css', 
                              '.js', '.ico', '.svg', '.woff', '.woff2', '.ttf']
            if any(url.lower().endswith(ext) for ext in skip_extensions):
                return False
            
            return True
        except Exception:
            return False
    
    def normalize_url(self, url: str) -> str:
        """Normalize URL by removing fragments and sorting query parameters."""
        parsed = urlparse(url)
        # Remove fragment
        normalized = f"{parsed.scheme}://{parsed.netloc}{parsed.path}"
        
        # Sort query parameters
        if parsed.query:
            params = parse_qs(parsed.query, keep_blank_values=True)
            sorted_params = sorted(params.items())
            query_string = urlencode(sorted_params, doseq=True)
            normalized += f"?{query_string}"
        
        return normalized
    
    def extract_links(self, html_content: str, current_url: str) -> List[str]:
        """Extract links from HTML content."""
        links = []
        soup = BeautifulSoup(html_content, 'html.parser')
        
        # Extract <a> tags
        for tag in soup.find_all('a', href=True):
            href = tag['href']
            absolute_url = urljoin(current_url, href)
            if self.is_valid_url(absolute_url):
                links.append(self.normalize_url(absolute_url))
        
        # Extract <form> action URLs
        for form in soup.find_all('form', action=True):
            action = form['action']
            absolute_url = urljoin(current_url, action)
            if self.is_valid_url(absolute_url):
                links.append(self.normalize_url(absolute_url))
        
        return links
    
    def extract_inputs(self, html_content: str, url: str, method: str = 'GET') -> List[Dict]:
        """Extract input fields from HTML forms."""
        inputs = []
        soup = BeautifulSoup(html_content, 'html.parser')
        
        forms = soup.find_all('form')
        for form in forms:
            form_method = form.get('method', 'GET').upper()
            form_action = form.get('action', '')
            form_url = urljoin(url, form_action) if form_action else url
            
            # Extract input fields
            form_inputs = []
            for input_tag in form.find_all(['input', 'textarea', 'select']):
                input_name = input_tag.get('name')
                input_type = input_tag.get('type', 'text').lower()
                
                if input_name:
                    form_inputs.append({
                        'name': input_name,
                        'type': input_type,
                        'value': input_tag.get('value', '')
                    })
            
            if form_inputs:
                inputs.append({
                    'url': self.normalize_url(form_url),
                    'method': form_method,
                    'inputs': form_inputs
                })
        
        # Also check for query parameters in URL
        parsed = urlparse(url)
        if parsed.query:
            params = parse_qs(parsed.query, keep_blank_values=True)
            if params:
                inputs.append({
                    'url': self.normalize_url(url),
                    'method': 'GET',
                    'inputs': [{'name': name, 'type': 'query', 'value': ''} 
                              for name in params.keys()]
                })
        
        return inputs
    
    def crawl(self) -> Dict:
        """
        Start crawling the web application.
        
        Returns:
            Dictionary containing discovered endpoints and input points
        """
        queue = deque([(self.base_url, 0)])
        all_inputs = []
        
        print(f"[*] Starting crawl of {self.base_url}")
        
        while queue:
            url, depth = queue.popleft()
            
            if depth > self.max_depth:
                continue
            
            normalized_url = self.normalize_url(url)
            if normalized_url in self.visited_urls:
                continue
            
            self.visited_urls.add(normalized_url)
            
            try:
                print(f"[*] Crawling: {url} (depth: {depth})")
                response = self.session.get(url, timeout=10, allow_redirects=True)
                
                if response.status_code == 200:
                    # Extract inputs from this page
                    page_inputs = self.extract_inputs(response.text, response.url, 'GET')
                    all_inputs.extend(page_inputs)
                    
                    # Extract links for further crawling
                    if depth < self.max_depth:
                        links = self.extract_links(response.text, response.url)
                        for link in links:
                            if link not in self.visited_urls:
                                queue.append((link, depth + 1))
                
                # Add endpoint info
                self.discovered_endpoints.append({
                    'url': normalized_url,
                    'status_code': response.status_code,
                    'method': 'GET',
                    'content_type': response.headers.get('Content-Type', '')
                })
                
                time.sleep(self.delay)
                
            except requests.exceptions.RequestException as e:
                print(f"[!] Error crawling {url}: {e}")
                continue
        
        # Deduplicate inputs
        unique_inputs = []
        seen = set()
        for inp in all_inputs:
            key = (inp['url'], inp['method'], tuple(sorted([i['name'] for i in inp['inputs']])))
            if key not in seen:
                seen.add(key)
                unique_inputs.append(inp)
        
        result = {
            'base_url': self.base_url,
            'total_endpoints': len(self.discovered_endpoints),
            'total_input_points': len(unique_inputs),
            'endpoints': self.discovered_endpoints,
            'input_points': unique_inputs
        }
        
        print(f"[+] Crawl complete: {len(self.discovered_endpoints)} endpoints, {len(unique_inputs)} input points")
        return result

