"""
GraphQL Scanner Module
"""

import re
import requests
import json
import time
from urllib.parse import urlparse

class GraphQLScanner:
    def __init__(self, base_url, session):
        self.base_url = base_url.rstrip('/')
        self.domain = urlparse(base_url).netloc
        self.session = session
        self.findings = []
        self.graphql_endpoints = [
            '/graphql',
            '/graphiql',
            '/v1/graphql',
            '/v2/graphql',
            '/api/graphql',
            '/api/v1/graphql',
            '/api/v2/graphql',
            '/graphql/v1',
            '/graphql/v2',
        ]

    def detect_graphql(self):
        """Detect GraphQL endpoints"""
        endpoints = []
        
        for endpoint in self.graphql_endpoints:
            test_urls = [
                f"{self.base_url}{endpoint}",
                f"https://{self.domain}{endpoint}",
            ]
            
            for url in test_urls:
                try:
                    # Introspection query
                    introspection_query = '''
                    {
                        __schema {
                            queryType { name }
                            mutationType { name }
                            subscriptionType { name }
                            types {
                                name
                                kind
                                fields { name }
                            }
                        }
                    }
                    '''
                    
                    response = self.session.post(url, json={'query': introspection_query}, timeout=10)
                    
                    if response.status_code == 200:
                        try:
                            data = response.json()
                            if 'data' in data and '__schema' in data['data']:
                                endpoints.append(url)
                        except:
                            pass
                        
                except Exception as e:
                    continue
        
        return endpoints

    def test_introspection(self, endpoint):
        """Test if introspection is enabled"""
        try:
            introspection_query = '''
            {
                __schema {
                    queryType { name }
                    mutationType { name }
                    types {
                        name
                        fields { name }
                    }
                }
            }
            '''
            
            response = self.session.post(endpoint, json={'query': introspection_query}, timeout=10)
            
            if response.status_code == 200:
                data = response.json()
                if 'data' in data and data['data'].get('__schema'):
                    return True
        except:
            pass
        
        return False

    def test_batching(self, endpoint):
        """Test for query batching vulnerabilities"""
        try:
            # Batch queries
            batch_query = [
                {'query': '{ __typename }'},
                {'query': '{ __typename }'},
                {'query': '{ __typename }'},
            ]
            
            response = self.session.post(endpoint, json=batch_query, timeout=10)
            
            if response.status_code == 200:
                try:
                    data = response.json()
                    if isinstance(data, list) and len(data) == 3:
                        return True
                except:
                    pass
        except:
            pass
        
        return False

    def test_dos_via_query(self, endpoint):
        """Test for DoS via complex queries"""
        try:
            # Deeply nested query
            nested_query = '''
            {
                deeply {
                    nested {
                        query {
                            even {
                                more {
                                    deep {
                                        query
                                    }
                                }
                            }
                        }
                    }
                }
            }
            '''
            
            start_time = time.time()
            response = self.session.post(endpoint, json={'query': nested_query}, timeout=10)
            execution_time = time.time() - start_time
            
            if execution_time > 3:
                return True, execution_time
        except:
            pass
        
        return False, 0

    def test_direct_object_access(self, endpoint, schema_types):
        """Test for direct object access vulnerabilities"""
        vulnerable_types = []
        
        for type_info in schema_types[:5]:  # Test first 5 types
            type_name = type_info.get('name', '')
            if type_name.startswith('__'):
                continue
            
            try:
                # Try to query the type directly
                query = f'''
                {{
                    {type_name}(first: 10) {{
                        id
                    }}
                }}
                '''
                
                response = self.session.post(endpoint, json={'query': query}, timeout=10)
                
                if response.status_code == 200:
                    data = response.json()
                    if 'data' in data and data['data'].get(type_name):
                        vulnerable_types.append(type_name)
                        
            except:
                continue
        
        return vulnerable_types

    def scan(self):
        """Main scanning function"""
        try:
            # Detect GraphQL endpoints
            endpoints = self.detect_graphql()
            
            if not endpoints:
                return self.findings
            
            for endpoint in endpoints:
                # Test introspection
                if self.test_introspection(endpoint):
                    self.findings.append({
                        'type': 'GraphQL',
                        'severity': 'Medium',
                        'title': 'GraphQL Introspection Enabled',
                        'description': 'GraphQL introspection is enabled, which exposes the entire schema and data structure to unauthorized users.',
                        'url': endpoint,
                        'remediation': 'Disable introspection in production. Use GraphQL query complexity analysis. Implement proper authentication and authorization.'
                    })
                
                # Test batching
                if self.test_batching(endpoint):
                    self.findings.append({
                        'type': 'GraphQL',
                        'severity': 'Medium',
                        'title': 'GraphQL Query Batching Enabled',
                        'description': 'GraphQL query batching is enabled, which could be abused for DoS attacks or brute force authentication.',
                        'url': endpoint,
                        'remediation': 'Disable query batching in production. Implement query depth limiting. Use rate limiting.'
                    })
                
                # Test DoS via complex queries
                is_vulnerable, exec_time = self.test_dos_via_query(endpoint)
                if is_vulnerable:
                    self.findings.append({
                        'type': 'GraphQL',
                        'severity': 'High',
                        'title': 'GraphQL Query Complexity DoS',
                        'description': f'Server vulnerable to DoS via complex queries. Query execution time: {exec_time:.2f}s',
                        'url': endpoint,
                        'remediation': 'Implement query complexity analysis and depth limiting. Use persisted queries. Set query timeout limits.'
                    })
            
        except Exception as e:
            print(f"GraphQL scanning error: {e}")
        
        return self.findings