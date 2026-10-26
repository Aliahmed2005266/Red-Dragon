"""
Site Mapper Module - 2D website mapping and relationship discovery
"""

import re
import requests
from urllib.parse import urlparse, urljoin
from collections import defaultdict
from bs4 import BeautifulSoup
import json

class SiteMapper:
    def __init__(self, base_url, session):
        self.base_url = base_url.rstrip('/')
        self.domain = urlparse(base_url).netloc
        if ':' in self.domain:
            self.domain = self.domain.split(':')[0]
        self.session = session
        self.nodes = []
        self.edges = []
        self.visited = set()
        
    def _normalize_url(self, url):
        """Normalize URL by removing fragments and trailing slashes"""
        parsed = urlparse(url)
        normalized = f"{parsed.scheme}://{parsed.netloc}{parsed.path.rstrip('/')}"
        if parsed.query:
            normalized += f"?{parsed.query}"
        return normalized
    
    def _is_same_domain(self, url):
        """Check if URL is on the same domain"""
        try:
            parsed = urlparse(url)
            host = parsed.netloc.split(':')[0]
            return host == self.domain or host.endswith('.' + self.domain)
        except:
            return False
    
    def _crawl_page(self, url, depth=0, max_depth=3):
        """Recursively crawl a page and extract links"""
        normalized = self._normalize_url(url)
        if normalized in self.visited or depth > max_depth:
            return []
        
        self.visited.add(normalized)
        page_data = {
            'url': normalized,
            'depth': depth,
            'title': '',
            'type': 'page',
            'links': [],
            'resources': [],
            'forms': [],
            'scripts': [],
            'status': 0
        }
        
        try:
            response = self.session.get(url, timeout=10)
            page_data['status'] = response.status_code
            page_data['size'] = len(response.text)
            page_data['content_type'] = response.headers.get('Content-Type', '')
            
            soup = BeautifulSoup(response.text, 'html.parser')
            
            # Extract title
            title_tag = soup.find('title')
            page_data['title'] = title_tag.string.strip() if title_tag and title_tag.string else ''
            
            # Extract all links
            for link in soup.find_all('a', href=True):
                href = link.get('href')
                if href and not href.startswith('#') and not href.startswith('javascript:'):
                    absolute = urljoin(url, href)
                    if self._is_same_domain(absolute):
                        normalized_link = self._normalize_url(absolute)
                        page_data['links'].append({
                            'url': normalized_link,
                            'text': link.get_text().strip()[:100],
                            'rel': link.get('rel', [''])[0] if link.get('rel') else ''
                        })
            
            # Extract forms
            for form in soup.find_all('form'):
                form_action = form.get('action', '')
                form_url = urljoin(url, form_action)
                form_method = form.get('method', 'get').upper()
                inputs = []
                for inp in form.find_all(['input', 'textarea', 'select']):
                    inputs.append({
                        'name': inp.get('name', ''),
                        'type': inp.get('type', 'text'),
                    })
                page_data['forms'].append({
                    'action': form_url,
                    'method': form_method,
                    'inputs': inputs
                })
            
            # Extract scripts
            for script in soup.find_all('script', src=True):
                src = script.get('src')
                page_data['scripts'].append(urljoin(url, src))
            
            # Extract resources
            for img in soup.find_all('img', src=True):
                page_data['resources'].append({
                    'url': urljoin(url, img.get('src')),
                    'type': 'image'
                })
            for css in soup.find_all('link', rel='stylesheet', href=True):
                page_data['resources'].append({
                    'url': urljoin(url, css.get('href')),
                    'type': 'stylesheet'
                })
            
            # Classify page type
            path = parsed.path.lower()
            if 'admin' in path or 'login' in path:
                page_data['type'] = 'admin'
            elif 'api' in path:
                page_data['type'] = 'api'
            elif 'wp-' in path:
                page_data['type'] = 'wordpress'
            elif page_data['forms']:
                page_data['type'] = 'form'
            elif page_data['links']:
                page_data['type'] = 'navigation'
            
            self.nodes.append(page_data)
            
            # Recursively crawl discovered links
            for link in page_data['links']:
                link_url = link['url']
                if link_url not in self.visited:
                    # Add edge
                    self.edges.append({
                        'from': normalized,
                        'to': link_url,
                        'type': 'link',
                        'text': link['text']
                    })
                    self._crawl_page(link_url, depth + 1, max_depth)
                    
        except Exception as e:
            page_data['error'] = str(e)
            if page_data not in self.nodes:
                self.nodes.append(page_data)
        
        return self.nodes
    
    def generate_relationships(self):
        """Analyze and extract relationships between pages"""
        relationships = []
        
        # Extract API relationships
        api_patterns = re.compile(r'/api/v?\d*/')
        apis = [n for n in self.nodes if api_patterns.search(n['url'])]
        
        if apis:
            relationships.append({
                'type': 'api_cluster',
                'title': f'API Cluster ({len(apis)} endpoints)',
                'urls': [a['url'] for a in apis],
                'description': 'Group of API endpoints that may share authentication'
            })
        
        # Extract admin relationships
        admin_pages = [n for n in self.nodes if n['type'] == 'admin']
        if admin_pages:
            relationships.append({
                'type': 'admin_cluster',
                'title': f'Admin Panel ({len(admin_pages)} pages)',
                'urls': [a['url'] for a in admin_pages],
                'description': 'Admin pages - potential privilege escalation targets'
            })
        
        # Pages that share common resources
        resource_map = defaultdict(list)
        for node in self.nodes:
            for res in node.get('resources', []):
                resource_map[res['url']].append(node['url'])
        
        shared_resources = {k: v for k, v in resource_map.items() if len(v) > 1}
        if shared_resources:
            relationships.append({
                'type': 'shared_resources',
                'title': f'Shared Resources ({len(shared_resources)} files)',
                'resources': dict(list(shared_resources.items())[:10]),
                'description': 'Resources shared across multiple pages'
            })
        
        return relationships
    
    def generate_map_data(self):
        """Generate complete site map data for 2D visualization"""
        
        # Generate nodes for vis.js format
        vis_nodes = []
        for i, node in enumerate(self.nodes):
            color = '#00d4ff'
            if node.get('type') == 'admin':
                color = '#dc3545'
            elif node.get('type') == 'api':
                color = '#fd7e14'
            elif node.get('type') == 'form':
                color = '#ffc107'
            elif node.get('type') == 'wordpress':
                color = '#17a2b8'
            
            size = 20
            if node.get('depth') == 0:
                size = 35
            elif node.get('depth') == 1:
                size = 25
            
            vis_nodes.append({
                'id': i,
                'label': node.get('title', node['url'].split('/')[-1])[:30],
                'title': f"URL: {node['url']}\nType: {node['type']}\nLinks: {len(node['links'])}\nForms: {len(node['forms'])}",
                'url': node['url'],
                'depth': node.get('depth', 0),
                'type': node.get('type', 'page'),
                'status': node.get('status', 0),
                'size': len(node['links']) + len(node['forms']) * 2,
                'color': color,
                'shape': 'dot',
                'borderWidth': 2,
                'borderColor': '#ffffff',
            })
        
        # Generate edges
        vis_edges = []
        seen_edges = set()
        for edge in self.edges:
            from_idx = next((i for i, n in enumerate(self.nodes) if n['url'] == edge['from']), None)
            to_idx = next((i for i, n in enumerate(self.nodes) if n['url'] == edge['to']), None)
            if from_idx is not None and to_idx is not None:
                edge_key = f"{from_idx}-{to_idx}"
                if edge_key not in seen_edges:
                    seen_edges.add(edge_key)
                    vis_edges.append({
                        'from': from_idx,
                        'to': to_idx,
                        'arrows': 'to',
                        'color': '#444',
                        'width': 0.5 if edge.get('text') else 1,
                        'title': edge.get('text', ''),
                    })
        
        # Generate relationship insights
        relationships = self.generate_relationships()
        
        return {
            'nodes': vis_nodes,
            'edges': vis_edges,
            'relationships': relationships,
            'stats': {
                'total_pages': len(self.nodes),
                'total_links': len(set(e['to'] for e in self.edges)),
                'total_forms': sum(len(n.get('forms', [])) for n in self.nodes),
                'admin_pages': len([n for n in self.nodes if n['type'] == 'admin']),
                'api_endpoints': len([n for n in self.nodes if n['type'] == 'api']),
            }
        }
    
    def scan(self, max_depth=3):
        """Main scanning function - crawls and maps the site"""
        self._crawl_page(self.base_url, 0, max_depth)
        return self.generate_map_data()