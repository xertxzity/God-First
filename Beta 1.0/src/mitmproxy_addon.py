"""
mitmproxy addon for unified backend routing
Routes Epic Games traffic between multiple backend services
"""

import logging
from mitmproxy import http
from mitmproxy import ctx


class UnifiedBackendRouter:
    def __init__(self):
        self.logger = logging.getLogger(__name__)
        
        # Backend routing configuration
        self.backend_routes = {
            # Main Fortnite backend services
            'account-public-service-prod.ol.epicgames.com': {'host': '127.0.0.1', 'port': 8443},
            'fortnite-public-service-prod11.ol.epicgames.com': {'host': '127.0.0.1', 'port': 8443},
            'fortnite-public-service-prod10.ol.epicgames.com': {'host': '127.0.0.1', 'port': 8443},
            'fortnite-public-service-prod08.ol.epicgames.com': {'host': '127.0.0.1', 'port': 8443},
            
            # Content and data services
            'content-public-service-prod.ol.epicgames.com': {'host': '127.0.0.1', 'port': 8443},
            'datarouter.ol.epicgames.com': {'host': '127.0.0.1', 'port': 8443},
            
            # Authentication and user services
            'lightswitch-public-service-prod.ol.epicgames.com': {'host': '127.0.0.1', 'port': 8443},
            'launcher-public-service-prod06.ol.epicgames.com': {'host': '127.0.0.1', 'port': 8443},
            'persona-public-service-prod.ol.epicgames.com': {'host': '127.0.0.1', 'port': 8443},
            
            # Social and tracking services
            'eulatracking-public-service-prod06.ol.epicgames.com': {'host': '127.0.0.1', 'port': 8443},
            'friends-public-service-prod06.ol.epicgames.com': {'host': '127.0.0.1', 'port': 8443},
            'friends-public-service-prod.ol.epicgames.com': {'host': '127.0.0.1', 'port': 8443},
            
            # Events and statistics
            'events-public-service-live.ol.epicgames.com': {'host': '127.0.0.1', 'port': 8443},
            'events-public-service-prod.ol.epicgames.com': {'host': '127.0.0.1', 'port': 8443},
            'statsproxy-public-service-live.ol.epicgames.com': {'host': '127.0.0.1', 'port': 8443},
        }
        
        # Future: Could route different services to different ports
        # self.backend_routes['some-service.com'] = {'host': '127.0.0.1', 'port': 8080}
        
    def request(self, flow: http.HTTPFlow) -> None:
        """Route Epic Games requests to appropriate backend services"""
        original_host = flow.request.pretty_host
        
        # Enhanced SSL bypass - handle more domains and scenarios
        bypass_domains = [
            'account-public-service-prod.ol.epicgames.com',
            'fortnite-public-service-prod11.ol.epicgames.com',
            'fortnite-public-service-prod10.ol.epicgames.com',
            'fortnite-public-service-prod08.ol.epicgames.com',
            'content-public-service-prod.ol.epicgames.com',
            'datarouter.ol.epicgames.com',
            'lightswitch-public-service-prod.ol.epicgames.com',
            'launcher-public-service-prod06.ol.epicgames.com',
            'persona-public-service-prod.ol.epicgames.com',
            'eulatracking-public-service-prod06.ol.epicgames.com',
            'friends-public-service-prod06.ol.epicgames.com',
            'friends-public-service-prod.ol.epicgames.com',
            'events-public-service-live.ol.epicgames.com',
            'events-public-service-prod.ol.epicgames.com',
            'statsproxy-public-service-live.ol.epicgames.com',
            # Additional domains for complete bypass
            '*.ol.epicgames.com',
            '*.epicgames.com',
            'epicgames.com',
            'ol.epicgames.com'
        ]
        
        # Check if this is an Epic Games domain that should be bypassed
        should_bypass = False
        for domain in bypass_domains:
            if domain.startswith('*'):
                # Wildcard matching
                if original_host.endswith(domain[1:]):
                    should_bypass = True
                    break
            elif original_host == domain:
                should_bypass = True
                break
        
        if should_bypass and original_host in self.backend_routes:
            route = self.backend_routes[original_host]
            
            self.logger.info(f"SSL Bypass: Routing {original_host}{flow.request.path} -> {route['host']}:{route['port']}")
            
            # Route to appropriate backend
            flow.request.host = route['host']
            flow.request.port = route['port']
            flow.request.scheme = "https"
            
            # Add routing headers for backend identification
            flow.request.headers["X-Fortnite-Routed"] = "true"
            flow.request.headers["X-Original-Host"] = original_host
            flow.request.headers["X-Backend-Route"] = f"{route['host']}:{route['port']}"
            flow.request.headers["X-SSL-Bypass"] = "true"
            
            # Remove any problematic headers that might interfere with SSL bypass
            headers_to_remove = [
                'X-Forwarded-Proto',
                'X-Forwarded-For',
                'X-Real-IP'
            ]
            for header in headers_to_remove:
                if header in flow.request.headers:
                    del flow.request.headers[header]
            
    def response(self, flow: http.HTTPFlow) -> None:
        """Handle responses from routed backend services"""
        if "X-Fortnite-Routed" in flow.request.headers:
            original_host = flow.request.headers.get("X-Original-Host", "unknown")
            backend_route = flow.request.headers.get("X-Backend-Route", "unknown")
            
            self.logger.info(f"Response from {backend_route} for {original_host}: {flow.response.status_code}")
            
            # Add CORS headers for compatibility
            flow.response.headers["Access-Control-Allow-Origin"] = "*"
            flow.response.headers["Access-Control-Allow-Methods"] = "GET, POST, PUT, DELETE, OPTIONS"
            flow.response.headers["Access-Control-Allow-Headers"] = "*"
            
            # Add routing info to response headers (for debugging)
            flow.response.headers["X-Routed-From"] = original_host
            flow.response.headers["X-Backend-Server"] = backend_route


addons = [UnifiedBackendRouter()]
