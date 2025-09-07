import asyncio
import ssl
import json
import logging
import os
from datetime import datetime, timedelta
from aiohttp import web, ClientSession
from aiohttp.web_response import Response
import aiohttp_cors
import base64
import uuid
from pathlib import Path
from .database import FortniteDatabase
from aiohttp.web import middleware

@middleware
async def log_request_info(request, handler):
    """Log all incoming requests for debugging"""
    print(f"[{datetime.now()}] Incoming {request.method} {request.url}")
    response = await handler(request)
    return response

class FortniteBackend:
    def __init__(self):
        self.app = web.Application(middlewares=[log_request_info])
        self.setup_logging()
        self.setup_routes()
        self.setup_cors()
        
        # Initialize database
        self.db = FortniteDatabase()
        
        # Load Season 7 Battle Pass configuration
        self.load_battle_pass_config()
        
        # Game data
        self.accounts = {}
        self.access_tokens = {}
        self.refresh_tokens = {}
        
        self.logger.info("Fortnite Backend initialized")
    
    def setup_logging(self):
        """Setup logging configuration"""
        if not os.path.exists('logs'):
            os.makedirs('logs')
        
        log_filename = f"logs/backend_{datetime.now().strftime('%Y%m%d_%H%M%S')}.log"
        logging.basicConfig(
            level=logging.INFO,
            format='%(asctime)s - %(levelname)s - %(message)s',
            handlers=[
                logging.FileHandler(log_filename),
                logging.StreamHandler()
            ]
        )
        self.logger = logging.getLogger(__name__)
    
    def setup_cors(self):
        """Setup CORS for cross-origin requests"""
        cors = aiohttp_cors.setup(self.app, defaults={
            "*": aiohttp_cors.ResourceOptions(
                allow_credentials=True,
                expose_headers="*",
                allow_headers="*",
                allow_methods="*"
            )
        })
        
        # Add CORS to specific routes only, avoiding the catch-all route
        routes_to_add_cors = [
            '/account/api/oauth/token',
            '/account/api/oauth/verify',
            '/fortnite/api/calendar/v1/timeline',
            '/fortnite/api/game/v2/profile',
            '/fortnite/api/game/v2/profile/*',
            '/fortnite/api/cloudstorage/system',
            '/fortnite/api/cloudstorage/system/*',
            '/fortnite/api/cloudstorage/user/*',
            '/.well-known/healthz'
        ]
        
        for route in list(self.app.router.routes()):
            if hasattr(route, 'resource') and hasattr(route.resource, 'canonical'):
                route_path = route.resource.canonical
                # Only add CORS to specific routes, skip catch-all
                if route_path in routes_to_add_cors or (route_path != '/{path:.*}' and not route_path.endswith('.*}')):
                    try:
                        cors.add(route)
                    except Exception as e:
                        self.logger.warning(f"Could not add CORS to route {route_path}: {e}")
    
    def setup_routes(self):
        """Setup all authentic Fortnite API routes"""
        # Real Epic Games Authentication endpoints
        self.app.router.add_post('/account/api/oauth/token', self.oauth_token)
        self.app.router.add_get('/account/api/oauth/verify', self.oauth_verify)
        self.app.router.add_get('/account/api/oauth/exchange', self.oauth_exchange)
        self.app.router.add_delete('/account/api/oauth/sessions/kill', self.oauth_kill)
        self.app.router.add_delete('/account/api/oauth/sessions/kill/{token}', self.oauth_kill_token)
        
        # Additional OAuth endpoints for complete bypass
        self.app.router.add_post('/account/api/oauth/device', self.oauth_device)
        self.app.router.add_post('/account/api/oauth/device/authorize', self.oauth_device_authorize)
        self.app.router.add_get('/account/api/oauth/device/verify', self.oauth_device_verify)
        self.app.router.add_post('/account/api/oauth/device/confirm', self.oauth_device_confirm)
        
        # Real Account Service endpoints
        self.app.router.add_get('/account/api/public/account', self.get_accounts)
        self.app.router.add_get('/account/api/public/account/{account_id}', self.get_account)
        self.app.router.add_get('/account/api/public/account/{account_id}/externalAuths', self.get_external_auths)
        self.app.router.add_get('/account/api/public/account/displayName/{display_name}', self.get_account_by_display_name)
        
        # Real Friends Service endpoints
        self.app.router.add_get('/friends/api/public/friends/{account_id}', self.get_friends)
        self.app.router.add_get('/friends/api/v1/{account_id}/summary', self.get_friends_summary)
        self.app.router.add_get('/friends/api/public/blocklist/{account_id}', self.get_blocklist)
        self.app.router.add_get('/friends/api/public/list/fortnite/{account_id}/recentPlayers', self.get_recent_players)
        
        # Real Fortnite Public Service endpoints
        self.app.router.add_post('/fortnite/api/game/v2/profile/{account_id}/client/{command}', self.mcp_operation)
        self.app.router.add_get('/fortnite/api/receipts/v1/account/{account_id}/receipts', self.get_receipts)
        self.app.router.add_get('/fortnite/api/storefront/v2/catalog', self.get_catalog)
        self.app.router.add_get('/fortnite/api/calendar/v1/timeline', self.get_timeline)
        self.app.router.add_get('/fortnite/api/game/v2/world/info', self.get_world_info)
        self.app.router.add_get('/fortnite/api/statsv2/account/{account_id}', self.get_stats)
        self.app.router.add_get('/fortnite/api/leaderboards/type/{stat_name}/stat/{stat_type}/window/{window}', self.get_leaderboards)
        
        # Battle Pass endpoints
        self.app.router.add_post('/fortnite/api/game/v2/profile/{account_id}/client/UnlockBattlePass', self.unlock_battle_pass)
        self.app.router.add_get('/fortnite/api/game/v2/battlepass/season/{season}', self.get_battle_pass_info)
        
        # Real Matchmaking Service endpoints
        self.app.router.add_get('/fortnite/api/matchmaking/session/findPlayer/{account_id}', self.find_player)
        self.app.router.add_get('/fortnite/api/game/v2/matchmakingservice/ticket/player/{account_id}', self.matchmaking_ticket)
        self.app.router.add_get('/fortnite/api/matchmaking/session/{session_id}', self.get_matchmaking_session)
        
        # Real Content Service endpoints
        self.app.router.add_get('/content/api/pages/fortnite-game', self.get_content_pages)
        self.app.router.add_get('/content/api/pages/fortnite-game/{region}', self.get_content_pages_region)
        
        # Real Version Check endpoints
        self.app.router.add_get('/fortnite/api/v2/versioncheck/{platform}', self.version_check)
        self.app.router.add_get('/fortnite/api/versioncheck', self.version_check_legacy)
        
        # Real Launcher Service endpoints
        self.app.router.add_get('/launcher/api/public/distributionpoints/', self.get_distribution_points)
        self.app.router.add_get('/launcher/api/public/assets/{platform}', self.get_assets)
        
        # Real Lightswitch Service endpoints
        self.app.router.add_get('/lightswitch/api/service/bulk/status', self.lightswitch_status)
        self.app.router.add_get('/lightswitch/api/service/Fortnite/status', self.fortnite_status)
        self.app.router.add_get('/lightswitch/api/service/{service_id}/status', self.service_status)
        
        # Real Persona Service endpoints
        self.app.router.add_get('/persona/api/public/account/lookup', self.persona_lookup)
        
        # Real Eulatracking Service endpoints
        self.app.router.add_get('/eulatracking/api/public/agreements/fn/account/{account_id}', self.eula_tracking)
        
        # Real Datarouter Service endpoints
        self.app.router.add_post('/datarouter/api/v1/public/data', self.datarouter_data)
        
        # Cloud Storage endpoints
        self.app.router.add_get('/fortnite/api/cloudstorage/system', self.get_system_cloudstorage)
        self.app.router.add_get('/fortnite/api/cloudstorage/system/{filename}', self.get_system_file)
        self.app.router.add_get('/fortnite/api/cloudstorage/user/{account_id}', self.get_user_cloudstorage)
        self.app.router.add_get('/fortnite/api/cloudstorage/user/{account_id}/{filename}', self.get_user_file)
        self.app.router.add_put('/fortnite/api/cloudstorage/user/{account_id}/{filename}', self.put_user_file)
        
        # Health endpoint
        self.app.router.add_get('/.well-known/healthz', self.healthz)
        
        # Catch-all must be last
        self.app.router.add_route('*', '/{path:.*}', self.catch_all)
    
    async def oauth_token(self, request):
        """Handle OAuth token requests - bypass login"""
        try:
            data = await request.post()
            grant_type = data.get('grant_type', '')
            client_id = data.get('client_id', 'ec684b8c687f479fadea3cb2ad83f5c6')
            
            self.logger.info(f"OAuth token request: {grant_type} from client {client_id}")
            
            # Handle different grant types
            if grant_type == 'client_credentials':
                # For client credentials, generate a service token
                account_id = f"service_{client_id}"
                access_token = base64.b64encode(f"eg1~service~{client_id}".encode()).decode()
                refresh_token = base64.b64encode(f"eg1~service~{client_id}~refresh".encode()).decode()
            elif grant_type == 'authorization_code':
                # For authorization code flow, generate user token
                account_id = str(uuid.uuid4()).replace('-', '')
                access_token = base64.b64encode(f"eg1~{account_id}".encode()).decode()
                refresh_token = base64.b64encode(f"eg1~{account_id}~refresh".encode()).decode()
            else:
                # Default: generate user token for any other grant type
                account_id = str(uuid.uuid4()).replace('-', '')
                access_token = base64.b64encode(f"eg1~{account_id}".encode()).decode()
                refresh_token = base64.b64encode(f"eg1~{account_id}~refresh".encode()).decode()
            
            # Store tokens
            self.access_tokens[access_token] = account_id
            self.refresh_tokens[refresh_token] = account_id
            
            # Store account (only for user accounts, not service accounts)
            if not account_id.startswith('service_'):
                self.accounts[account_id] = {
                    'id': account_id,
                    'displayName': 'FortnitePlayer',
                    'email': 'player@fortnite.local',
                    'failedLoginAttempts': 0,
                    'lastLogin': datetime.utcnow().isoformat() + 'Z',
                    'numberOfDisplayNameChanges': 0,
                    'ageGroup': 'UNKNOWN',
                    'headless': False,
                    'country': 'US',
                    'lastName': 'Player',
                    'firstName': 'Fortnite',
                    'preferredLanguage': 'en',
                    'canUpdateDisplayName': True,
                    'tfaEnabled': False,
                    'emailVerified': True,
                    'minorVerified': False,
                    'minorExpected': False,
                    'minorStatus': 'UNKNOWN'
                }
            
            # Enhanced response data with more fields for better compatibility
            response_data = {
                'access_token': access_token,
                'expires_in': 28800,
                'expires_at': '9999-12-31T23:59:59.999Z',
                'token_type': 'bearer',
                'account_id': account_id,
                'client_id': client_id,
                'internal_client': True,
                'client_service': 'fortnite',
                'scope': ['basic_account_client', 'friends_list', 'presence', 'profile'],
                'refresh_token': refresh_token,
                'refresh_expires': 86400,
                'refresh_expires_at': '9999-12-31T23:59:59.999Z',
                'device_id': str(uuid.uuid4()),
                'application_id': client_id,
                'product_id': 'prod-fn'
            }
            
            self.logger.info(f"Generated token for account {account_id}")
            return web.json_response(response_data)
            
        except Exception as e:
            self.logger.error(f"OAuth token error: {str(e)}")
            return web.json_response({'error': 'invalid_request', 'error_description': str(e)}, status=400)
    
    async def oauth_verify(self, request):
        """Verify OAuth token"""
        auth_header = request.headers.get('Authorization', '')
        if not auth_header.startswith('Bearer '):
            return web.json_response({'error': 'invalid_token'}, status=401)
        
        token = auth_header[7:]
        account_id = self.access_tokens.get(token)
        
        if not account_id:
            return web.json_response({'error': 'invalid_token'}, status=401)
        
        account = self.accounts.get(account_id, {})
        
        response_data = {
            'token': token,
            'session_id': str(uuid.uuid4()).replace('-', ''),
            'token_type': 'bearer',
            'client_id': 'ec684b8c687f479fadea3cb2ad83f5c6',
            'internal_client': True,
            'client_service': 'fortnite',
            'account_id': account_id,
            'expires_in': 28800,
            'expires_at': (datetime.utcnow() + timedelta(hours=8)).isoformat() + 'Z',
            'auth_method': 'exchange_code',
            'display_name': account.get('displayName', 'FortnitePlayer'),
            'app': 'fortnite',
            'in_app_id': account_id,
            'product_id': 'prod-fn'
        }
        
        return web.json_response(response_data)
    
    async def oauth_kill(self, request):
        """Kill OAuth session"""
        return web.Response(status=204)
    
    async def oauth_kill_token(self, request):
        """Kill specific OAuth token"""
        return web.Response(status=204)
    
    async def oauth_exchange(self, request):
        """OAuth exchange endpoint"""
        auth_header = request.headers.get('Authorization', '')
        if not auth_header.startswith('Bearer '):
            return web.json_response({'error': 'invalid_token'}, status=401)
        
        # Generate exchange code
        exchange_code = base64.b64encode(f"exchange_{uuid.uuid4()}".encode()).decode()
        
        return web.json_response({
            'expiresInSeconds': 300,
            'code': exchange_code,
            'creatingClientId': 'ec684b8c687f479fadea3cb2ad83f5c6'
        })
    
    async def oauth_device(self, request):
        """OAuth device flow - bypass device authentication"""
        try:
            data = await request.json() if request.content_length else {}
            client_id = data.get('client_id', 'ec684b8c687f479fadea3cb2ad83f5c6')
            
            # Generate device code
            device_code = base64.b64encode(f"device_{uuid.uuid4()}".encode()).decode()
            user_code = f"{uuid.uuid4().hex[:4].upper()}-{uuid.uuid4().hex[:4].upper()}"
            
            self.logger.info(f"Device flow initiated for client {client_id}")
            
            return web.json_response({
                'device_code': device_code,
                'user_code': user_code,
                'verification_uri': 'https://www.epicgames.com/activate',
                'verification_uri_complete': f'https://www.epicgames.com/activate?user_code={user_code}',
                'expires_in': 600,
                'interval': 5
            })
        except Exception as e:
            self.logger.error(f"OAuth device error: {str(e)}")
            return web.json_response({'error': 'invalid_request'}, status=400)
    
    async def oauth_device_authorize(self, request):
        """OAuth device authorization - auto-approve"""
        try:
            data = await request.json() if request.content_length else {}
            device_code = data.get('device_code', '')
            
            self.logger.info(f"Device authorization for device code: {device_code[:20]}...")
            
            # Auto-approve device authorization
            return web.json_response({
                'status': 'approved',
                'device_code': device_code
            })
        except Exception as e:
            self.logger.error(f"OAuth device authorize error: {str(e)}")
            return web.json_response({'error': 'invalid_request'}, status=400)
    
    async def oauth_device_verify(self, request):
        """OAuth device verification - return success"""
        device_code = request.query.get('device_code', '')
        
        if device_code:
            self.logger.info(f"Device verification for device code: {device_code[:20]}...")
            
            # Generate access token for device
            account_id = str(uuid.uuid4()).replace('-', '')
            access_token = base64.b64encode(f"eg1~device~{account_id}".encode()).decode()
            
            return web.json_response({
                'access_token': access_token,
                'token_type': 'bearer',
                'expires_in': 28800,
                'expires_at': '9999-12-31T23:59:59.999Z',
                'account_id': account_id,
                'client_id': 'ec684b8c687f479fadea3cb2ad83f5c6'
            })
        
        return web.json_response({'error': 'invalid_device_code'}, status=400)
    
    async def oauth_device_confirm(self, request):
        """OAuth device confirmation - auto-confirm"""
        try:
            data = await request.json() if request.content_length else {}
            device_code = data.get('device_code', '')
            
            self.logger.info(f"Device confirmation for device code: {device_code[:20]}...")
            
            # Auto-confirm device
            return web.json_response({
                'status': 'confirmed',
                'device_code': device_code
            })
        except Exception as e:
            self.logger.error(f"OAuth device confirm error: {str(e)}")
            return web.json_response({'error': 'invalid_request'}, status=400)
    
    async def get_accounts(self, request):
        """Get account information"""
        account_ids = request.query.get('accountId', '').split(',')
        accounts = []
        
        for account_id in account_ids:
            if account_id in self.accounts:
                accounts.append(self.accounts[account_id])
        
        return web.json_response(accounts)
    
    async def get_account(self, request):
        """Get single account"""
        account_id = request.match_info['account_id']
        account = self.accounts.get(account_id)
        
        if not account:
            return web.json_response({'error': 'account_not_found'}, status=404)
        
        return web.json_response(account)
    
    async def get_external_auths(self, request):
        """Get external authentications"""
        return web.json_response([])
    
    async def get_account_by_display_name(self, request):
        """Get account by display name"""
        display_name = request.match_info['display_name']
        
        # Search for account with matching display name
        for account_id, account in self.accounts.items():
            if account.get('displayName', '').lower() == display_name.lower():
                return web.json_response(account)
        
        return web.json_response({'error': 'account_not_found'}, status=404)
    
    async def get_friends(self, request):
        """Get friends list"""
        # In a real implementation, this would query the database
        # For now, return mock friends data
        mock_friends = [
            {
                'accountId': 'friend_account_1',
                'status': 'ACCEPTED',
                'direction': 'OUTBOUND',
                'created': '2018-12-06T14:00:00.000Z',
                'favorite': False
            },
            {
                'accountId': 'friend_account_2', 
                'status': 'ACCEPTED',
                'direction': 'INBOUND',
                'created': '2018-12-07T10:30:00.000Z',
                'favorite': True
            }
        ]
        return web.json_response(mock_friends)
    
    async def get_friends_summary(self, request):
        """Get friends summary"""
        return web.json_response({
            'friends': [
                {
                    'accountId': 'friend_account_1',
                    'displayName': 'FortniteFriend1',
                    'status': 'ACCEPTED'
                },
                {
                    'accountId': 'friend_account_2',
                    'displayName': 'FortniteFriend2', 
                    'status': 'ACCEPTED'
                }
            ],
            'incoming': [],
            'outgoing': [],
            'suggested': [
                {
                    'accountId': 'suggested_friend_1',
                    'displayName': 'SuggestedPlayer1',
                    'mutualFriends': 2
                }
            ]
        })
    
    async def get_blocklist(self, request):
        """Get blocked users list"""
        return web.json_response([])
    
    async def get_recent_players(self, request):
        """Get recent players"""
        return web.json_response([])
    
    async def get_world_info(self, request):
        """Get Fortnite world information"""
        return web.json_response({
            'theaters': [],
            'missions': [],
            'missionAlerts': []
        })
    
    async def get_stats(self, request):
        """Get player statistics"""
        account_id = request.match_info['account_id']
        
        # Get user from database to check if they exist
        user = self.db.get_user(account_id)
        if not user:
            self.db.create_user(account_id, f'Player_{account_id[:8]}', f'{account_id}@fortnite.local')
        
        # Mock Season 7 stats - in real implementation, query from database
        return web.json_response({
            'accountId': account_id,
            'stats': {
                'br_placetop1_solo_m0_p2': {'value': 5},  # Solo wins
                'br_placetop1_duo_m0_p2': {'value': 3},   # Duo wins  
                'br_placetop1_squad_m0_p2': {'value': 8}, # Squad wins
                'br_kills_solo_m0_p2': {'value': 127},    # Solo kills
                'br_kills_duo_m0_p2': {'value': 89},      # Duo kills
                'br_kills_squad_m0_p2': {'value': 156},   # Squad kills
                'br_matchesplayed_solo_m0_p2': {'value': 45},  # Solo matches
                'br_matchesplayed_duo_m0_p2': {'value': 32},   # Duo matches
                'br_matchesplayed_squad_m0_p2': {'value': 67}, # Squad matches
                'br_placetop10_solo_m0_p2': {'value': 23},     # Solo top 10
                'br_placetop5_duo_m0_p2': {'value': 18},       # Duo top 5
                'br_placetop3_squad_m0_p2': {'value': 31},     # Squad top 3
                'br_minutesplayed_solo_m0_p2': {'value': 892}, # Solo minutes
                'br_minutesplayed_duo_m0_p2': {'value': 654},  # Duo minutes
                'br_minutesplayed_squad_m0_p2': {'value': 1123} # Squad minutes
            },
            'groupStats': {}
        })
    
    async def get_leaderboards(self, request):
        """Get leaderboards"""
        stat_name = request.match_info.get('stat_name', 'wins')
        window = request.match_info.get('window', 'weekly')
        
        # Mock leaderboard data for Season 7
        leaderboard_entries = [
            {
                'accountId': 'top_player_1',
                'displayName': 'FortniteChampion',
                'value': 247,
                'rank': 1
            },
            {
                'accountId': 'top_player_2', 
                'displayName': 'VictoryRoyale',
                'value': 198,
                'rank': 2
            },
            {
                'accountId': 'top_player_3',
                'displayName': 'BattleBusLegend',
                'value': 156,
                'rank': 3
            },
            {
                'accountId': 'top_player_4',
                'displayName': 'TiltedTowersPro',
                'value': 134,
                'rank': 4
            },
            {
                'accountId': 'top_player_5',
                'displayName': 'LootLakeHero',
                'value': 112,
                'rank': 5
            }
        ]
        
        return web.json_response({
            'entries': leaderboard_entries,
            'statName': stat_name,
            'statWindow': window
        })
    
    async def mcp_operation(self, request):
        """Handle MCP (McpProfile) operations"""
        account_id = request.match_info['account_id']
        command = request.match_info['command']
        
        self.logger.info(f"MCP operation: {command} for account {account_id}")
        
        # Get request data
        try:
            request_data = await request.json() if request.content_length else {}
        except:
            request_data = {}
        
        # Get profile ID from query params or default to athena
        profile_id = request.query.get('profileId', 'athena')
        
        # Ensure user exists
        user = self.db.get_user(account_id)
        if not user:
            self.db.create_user(account_id, f'Player_{account_id[:8]}', f'{account_id}@fortnite.local')
            user = self.db.get_user(account_id)
        
        # Get current profile
        profile = self.db.get_profile(account_id, profile_id)
        if not profile:
            self.db.create_default_profiles(account_id)
            profile = self.db.get_profile(account_id, profile_id)
        
        # Handle different MCP commands
        profile_changes = []
        
        if command == 'QueryProfile':
            # Load user items into profile
            user_items = self.db.get_user_items(account_id)
            profile['items'] = user_items
            
            # Update stats with current user data
            if profile_id == 'athena':
                profile['stats']['attributes'].update({
                    'level': user['level'],
                    'xp': user['xp'],
                    'accountLevel': user['level'],
                    'book_level': user['battle_pass_tier'],
                    'book_xp': user['battle_pass_xp'],
                    'book_purchased': user['battle_pass_purchased']
                })
            elif profile_id == 'common_core':
                profile['stats']['attributes']['mtx_purchase_history'] = {
                    'refundsUsed': 0,
                    'refundCredits': 3
                }
        
        elif command == 'EquipBattleRoyaleCustomization':
            # Handle locker customization
            slot_name = request_data.get('slotName', '')
            item_to_slot = request_data.get('itemToSlot', '')
            index_within_slot = request_data.get('indexWithinSlot', 0)
            
            if slot_name and item_to_slot:
                # Update locker in database
                self.db.update_locker_slot(account_id, slot_name, item_to_slot)
                
                # Add profile change
                profile_changes.append({
                    'changeType': 'statModified',
                    'name': f'locker_slots_data.slots.{slot_name}',
                    'value': {
                        'items': [item_to_slot],
                        'activeVariants': []
                    }
                })
        
        elif command == 'SetCosmeticLockerSlot':
            # Handle individual locker slot updates
            category = request_data.get('category', '')
            item_to_slot = request_data.get('itemToSlot', '')
            slot_index = request_data.get('slotIndex', 0)
            
            if category:
                self.db.update_locker_slot(account_id, category, item_to_slot)
                
                profile_changes.append({
                    'changeType': 'statModified',
                    'name': f'locker_slots_data.slots.{category}',
                    'value': {
                        'items': [item_to_slot] if item_to_slot else [],
                        'activeVariants': []
                    }
                })
        
        elif command == 'PurchaseCatalogEntry':
            # Handle item purchases
            offer_id = request_data.get('offerId', '')
            purchase_quantity = request_data.get('purchaseQuantity', 1)
            currency = request_data.get('currency', 'MtxCurrency')
            
            # Mock purchase - grant item and deduct currency
            if offer_id:
                # For demo, grant a random item
                item_id = f'purchased_item_{uuid.uuid4().hex[:8]}'
                self.db.grant_item(account_id, item_id, purchase_quantity)
                
                profile_changes.append({
                    'changeType': 'itemAdded',
                    'itemId': item_id,
                    'item': {
                        'templateId': f'AthenaCharacter:{item_id}',
                        'attributes': {},
                        'quantity': purchase_quantity
                    }
                })
        
        # Update profile revision
        new_revision = self.db.update_profile(account_id, profile_id, profile)
        
        # Build response
        response_data = {
            'profileRevision': new_revision,
            'profileId': profile_id,
            'profileChangesBaseRevision': profile.get('profileRevision', 1),
            'profileChanges': profile_changes,
            'profileCommandRevision': new_revision,
            'serverTime': datetime.utcnow().isoformat() + 'Z',
            'responseVersion': 1
        }
        
        return web.json_response(response_data)
    
    async def get_receipts(self, request):
        """Get purchase receipts"""
        return web.json_response([])
    
    async def get_catalog(self, request):
        """Get item shop catalog - Season 7.40 shop"""
        # Season 7.40 featured items and daily shop
        catalog_data = {
            'refreshIntervalHrs': 24,
            'dailyPurchaseHrs': 24,
            'expiration': (datetime.utcnow() + timedelta(hours=24)).isoformat() + 'Z',
            'storefronts': [
                {
                    'name': 'BRFeaturedStorefront',
                    'catalogEntries': [
                        {
                            'offerId': 'featured_raven_bundle',
                            'devName': 'Raven Bundle',
                            'offerType': 'StaticPrice',
                            'prices': [{
                                'currencyType': 'MtxCurrency',
                                'currencySubType': '',
                                'regularPrice': 2000,
                                'finalPrice': 2000,
                                'saleExpiration': '9999-12-31T23:59:59.999Z',
                                'basePrice': 2000
                            }],
                            'categories': ['Panel01'],
                            'catalogGroup': '',
                            'catalogGroupPriority': 0,
                            'sortPriority': 0,
                            'title': 'Raven',
                            'shortDescription': 'Dark and mysterious',
                            'description': 'Embrace the darkness with this legendary outfit.',
                            'displayAssetPath': '/Game/Catalog/DisplayAssets/DA_Featured_Raven.DA_Featured_Raven',
                            'itemGrants': [{
                                'templateId': 'AthenaCharacter:CID_028_Athena_Commando_F',
                                'quantity': 1
                            }],
                            'requirements': [],
                            'metaInfo': [{
                                'key': 'SectionId',
                                'value': 'Featured'
                            }],
                            'catalogGroupPriority': 0,
                            'refundable': True,
                            'dailyLimit': -1,
                            'weeklyLimit': -1,
                            'monthlyLimit': -1,
                            'appStoreId': []
                        },
                        {
                            'offerId': 'featured_skull_trooper',
                            'devName': 'Skull Trooper',
                            'offerType': 'StaticPrice',
                            'prices': [{
                                'currencyType': 'MtxCurrency',
                                'currencySubType': '',
                                'regularPrice': 1500,
                                'finalPrice': 1500,
                                'saleExpiration': '9999-12-31T23:59:59.999Z',
                                'basePrice': 1500
                            }],
                            'categories': ['Panel02'],
                            'title': 'Skull Trooper',
                            'shortDescription': 'Spooky scary skeleton',
                            'description': 'The original Halloween outfit returns.',
                            'displayAssetPath': '/Game/Catalog/DisplayAssets/DA_Featured_SkullTrooper.DA_Featured_SkullTrooper',
                            'itemGrants': [{
                                'templateId': 'AthenaCharacter:CID_029_Athena_Commando_F_Halloween',
                                'quantity': 1
                            }],
                            'requirements': [],
                            'metaInfo': [{
                                'key': 'SectionId',
                                'value': 'Featured'
                            }],
                            'refundable': True,
                            'dailyLimit': -1,
                            'weeklyLimit': -1,
                            'monthlyLimit': -1,
                            'appStoreId': []
                        }
                    ]
                },
                {
                    'name': 'BRDailyStorefront',
                    'catalogEntries': [
                        {
                            'offerId': 'daily_reaper_pickaxe',
                            'devName': 'Reaper Pickaxe',
                            'offerType': 'StaticPrice',
                            'prices': [{
                                'currencyType': 'MtxCurrency',
                                'currencySubType': '',
                                'regularPrice': 800,
                                'finalPrice': 800,
                                'saleExpiration': '9999-12-31T23:59:59.999Z',
                                'basePrice': 800
                            }],
                            'categories': ['Panel01'],
                            'title': 'Reaper',
                            'shortDescription': 'Harvest with style',
                            'description': 'A legendary harvesting tool.',
                            'displayAssetPath': '/Game/Catalog/DisplayAssets/DA_Daily_Reaper.DA_Daily_Reaper',
                            'itemGrants': [{
                                'templateId': 'AthenaPickaxe:Pickaxe_ID_015_Halloween',
                                'quantity': 1
                            }],
                            'requirements': [],
                            'metaInfo': [{
                                'key': 'SectionId',
                                'value': 'Daily'
                            }],
                            'refundable': True,
                            'dailyLimit': -1,
                            'weeklyLimit': -1,
                            'monthlyLimit': -1,
                            'appStoreId': []
                        },
                        {
                            'offerId': 'daily_floss_emote',
                            'devName': 'Floss Emote',
                            'offerType': 'StaticPrice',
                            'prices': [{
                                'currencyType': 'MtxCurrency',
                                'currencySubType': '',
                                'regularPrice': 500,
                                'finalPrice': 500,
                                'saleExpiration': '9999-12-31T23:59:59.999Z',
                                'basePrice': 500
                            }],
                            'categories': ['Panel02'],
                            'title': 'Floss',
                            'shortDescription': 'Dental hygiene dance',
                            'description': 'Show off your moves with this iconic emote.',
                            'displayAssetPath': '/Game/Catalog/DisplayAssets/DA_Daily_Floss.DA_Daily_Floss',
                            'itemGrants': [{
                                'templateId': 'AthenaDance:EID_Floss',
                                'quantity': 1
                            }],
                            'requirements': [],
                            'metaInfo': [{
                                'key': 'SectionId',
                                'value': 'Daily'
                            }],
                            'refundable': True,
                            'dailyLimit': -1,
                            'weeklyLimit': -1,
                            'monthlyLimit': -1,
                            'appStoreId': []
                        }
                    ]
                },
                {
                    'name': 'BRCurrencyStorefront',
                    'catalogEntries': [
                        {
                            'offerId': 'vbucks_1000',
                            'devName': '1,000 V-Bucks',
                            'offerType': 'StaticPrice',
                            'prices': [{
                                'currencyType': 'RealMoney',
                                'currencySubType': 'USD',
                                'regularPrice': 999,
                                'finalPrice': 999,
                                'saleExpiration': '9999-12-31T23:59:59.999Z',
                                'basePrice': 999
                            }],
                            'categories': ['Panel01'],
                            'title': '1,000 V-Bucks',
                            'shortDescription': 'In-game currency',
                            'description': 'Purchase V-Bucks to buy cosmetic items.',
                            'displayAssetPath': '/Game/Catalog/DisplayAssets/DA_VBucks_1000.DA_VBucks_1000',
                            'itemGrants': [{
                                'templateId': 'Currency:MtxPurchased',
                                'quantity': 1000
                            }],
                            'requirements': [],
                            'metaInfo': [{
                                'key': 'SectionId',
                                'value': 'VBucks'
                            }],
                            'refundable': False,
                            'dailyLimit': -1,
                            'weeklyLimit': -1,
                            'monthlyLimit': -1,
                            'appStoreId': ['com.epicgames.fortnite.vbucks1000']
                        },
                        {
                            'offerId': 'vbucks_2800',
                            'devName': '2,800 V-Bucks',
                            'offerType': 'StaticPrice',
                            'prices': [{
                                'currencyType': 'RealMoney',
                                'currencySubType': 'USD',
                                'regularPrice': 2499,
                                'finalPrice': 2499,
                                'saleExpiration': '9999-12-31T23:59:59.999Z',
                                'basePrice': 2499
                            }],
                            'categories': ['Panel02'],
                            'title': '2,800 V-Bucks',
                            'shortDescription': 'In-game currency',
                            'description': 'Purchase V-Bucks to buy cosmetic items. Best value!',
                            'displayAssetPath': '/Game/Catalog/DisplayAssets/DA_VBucks_2800.DA_VBucks_2800',
                            'itemGrants': [{
                                'templateId': 'Currency:MtxPurchased',
                                'quantity': 2800
                            }],
                            'requirements': [],
                            'metaInfo': [{
                                'key': 'SectionId',
                                'value': 'VBucks'
                            }],
                            'refundable': False,
                            'dailyLimit': -1,
                            'weeklyLimit': -1,
                            'monthlyLimit': -1,
                            'appStoreId': ['com.epicgames.fortnite.vbucks2800']
                        }
                    ]
                }
            ]
        }
        
        return web.json_response(catalog_data)
    
    async def get_timeline(self, request):
        """Get game timeline - Season 7.40 authentic data"""
        # Real Season 7.40 timeline data <mcreference link="https://dev.epicgames.com/docs/web-api-ref/authentication" index="1">1</mcreference>
        timeline_data = {
            'channels': {
                'standalone-store': {
                    'states': [{
                        'validFrom': '2019-02-01T00:00:00.000Z',
                        'activeEvents': [],
                        'state': {
                            'activePurchaseLimitingEventIds': [],
                            'storefront': {
                                'refreshIntervalHrs': 24,
                                'dailyPurchaseHrs': 24
                            },
                            'rmtPromotionConfig': [],
                            'storeEnd': '2025-12-31T23:59:59.999Z'
                        }
                    }],
                    'cacheExpire': '2025-12-31T23:59:59.999Z'
                },
                'client-matchmaking': {
                    'states': [{
                        'validFrom': '2019-02-01T00:00:00.000Z',
                        'activeEvents': [],
                        'state': {
                            'region': {
                                'NAE': {
                                    'eventFlagsForcedOff': []
                                },
                                'NAW': {
                                    'eventFlagsForcedOff': []
                                },
                                'EU': {
                                    'eventFlagsForcedOff': []
                                },
                                'OCE': {
                                    'eventFlagsForcedOff': []
                                },
                                'BR': {
                                    'eventFlagsForcedOff': []
                                },
                                'ASIA': {
                                    'eventFlagsForcedOff': []
                                }
                            }
                        }
                    }],
                    'cacheExpire': '2025-12-31T23:59:59.999Z'
                },
                'tk': {
                    'states': [{
                        'validFrom': '2019-02-01T00:00:00.000Z',
                        'activeEvents': [],
                        'state': {
                            'k': [
                                'https://account-public-service-prod.ol.epicgames.com:443',
                                'https://fortnite-public-service-prod11.ol.epicgames.com:443'
                            ]
                        }
                    }],
                    'cacheExpire': '2025-12-31T23:59:59.999Z'
                },
                'featured-islands': {
                    'states': [{
                        'validFrom': '2019-02-01T00:00:00.000Z',
                        'activeEvents': [],
                        'state': {
                            'islandCodes': [],
                            'playlistCuratedContent': {},
                            'playlistCuratedHub': {},
                            'islandTemplates': []
                        }
                    }],
                    'cacheExpire': '2025-12-31T23:59:59.999Z'
                }
            },
            'eventsTimeOffsetHrs': 0,
            'cacheIntervalMins': 10,
            'currentTime': datetime.utcnow().isoformat() + 'Z'
        }
        return web.json_response(timeline_data)
    
    async def find_player(self, request):
        """Find player for matchmaking"""
        return web.json_response([])
    
    async def matchmaking_ticket(self, request):
        """Get matchmaking ticket"""
        return web.json_response({
            'serviceUrl': 'ws://localhost:443',
            'ticketType': 'mms-player',
            'payload': 'placeholder_payload',
            'signature': 'placeholder_signature'
        })
    
    async def get_matchmaking_session(self, request):
        """Get matchmaking session"""
        session_id = request.match_info['session_id']
        return web.json_response({
            'id': session_id,
            'ownerId': str(uuid.uuid4()).replace('-', ''),
            'ownerName': '[DS]fortnite-liveeugcec1c2e30',
            'serverName': '',
            'serverAddress': '127.0.0.1',
            'serverPort': 7777,
            'maxPublicPlayers': 220,
            'openPublicPlayers': 175,
            'maxPrivatePlayers': 0,
            'openPrivatePlayers': 0,
            'attributes': {},
            'publicPlayers': [],
            'privatePlayers': [],
            'totalPlayers': 45,
            'allowJoinInProgress': False,
            'shouldAdvertise': False,
            'isDedicated': False,
            'usesStats': False,
            'allowInvites': False,
            'usesPresence': False,
            'allowJoinViaPresence': True,
            'allowJoinViaPresenceFriendsOnly': False,
            'buildUniqueId': '0',
            'lastUpdated': datetime.utcnow().isoformat() + 'Z',
            'started': False
        })
    
    async def get_content_pages(self, request):
        """Get content pages with rotating news feeds and dynamic backgrounds"""
        # Generate dynamic content based on current time for rotation
        current_hour = datetime.utcnow().hour
        
        # Rotating news feeds for Season 7.40
        news_rotation = [
            {
                'entryType': 'Text',
                'image': 'https://cdn2.unrealengine.com/Fortnite/fortnite-game/battleroyalenews/BR07_News_Featured_IceStorm-1920x1080-1920x1080-c2f36f1e2d0c7e6b9c4b8a5d4e2f1a3b4c5d6e7f.jpg',
                'tileImage': 'https://cdn2.unrealengine.com/Fortnite/fortnite-game/battleroyalenews/BR07_News_Tile_IceStorm-512x512-512x512-a1b2c3d4e5f6789012345678901234567890abcd.jpg',
                'hidden': False,
                'messageType': 'normal',
                '_type': 'CommonUI Simple Message MOTD',
                'title': 'Season 7: Ice Storm Event',
                'body': 'The Ice King has brought eternal winter to the island! Drop in and experience the frozen landscape with new challenges and rewards.',
                'videoString': '',
                'tabTitleOverride': 'Ice Storm',
                'buttonTextOverride': 'Play Now',
                'sortingPriority': 10,
                'id': 'season7-ice-storm'
            },
            {
                'entryType': 'Text', 
                'image': 'https://cdn2.unrealengine.com/Fortnite/fortnite-game/battleroyalenews/BR07_News_Featured_BattlePass-1920x1080-1920x1080-b3c4d5e6f7890123456789012345678901234567.jpg',
                'tileImage': 'https://cdn2.unrealengine.com/Fortnite/fortnite-game/battleroyalenews/BR07_News_Tile_BattlePass-512x512-512x512-c4d5e6f7890123456789012345678901234567890.jpg',
                'hidden': False,
                'messageType': 'normal',
                '_type': 'CommonUI Simple Message MOTD',
                'title': 'Season 7 Battle Pass',
                'body': 'Unlock over 100 new rewards including the legendary Ice King outfit! Purchase the Battle Pass and start earning exclusive items.',
                'videoString': '',
                'tabTitleOverride': 'Battle Pass',
                'buttonTextOverride': 'Get Battle Pass',
                'sortingPriority': 9,
                'id': 'season7-battle-pass'
            },
            {
                'entryType': 'Text',
                'image': 'https://cdn2.unrealengine.com/Fortnite/fortnite-game/battleroyalenews/BR07_News_Featured_ItemShop-1920x1080-1920x1080-d5e6f7890123456789012345678901234567890123.jpg',
                'tileImage': 'https://cdn2.unrealengine.com/Fortnite/fortnite-game/battleroyalenews/BR07_News_Tile_ItemShop-512x512-512x512-e6f7890123456789012345678901234567890123456.jpg',
                'hidden': False,
                'messageType': 'normal',
                '_type': 'CommonUI Simple Message MOTD',
                'title': 'New Items in Shop',
                'body': 'Check out the latest cosmetics including the Raven outfit and Reaper pickaxe! Shop refreshes daily with new items.',
                'videoString': '',
                'tabTitleOverride': 'Item Shop',
                'buttonTextOverride': 'Shop Now',
                'sortingPriority': 8,
                'id': 'season7-item-shop'
            },
            {
                'entryType': 'Text',
                'image': 'https://cdn2.unrealengine.com/Fortnite/fortnite-game/battleroyalenews/BR07_News_Featured_Creative-1920x1080-1920x1080-f7890123456789012345678901234567890123456789.jpg',
                'tileImage': 'https://cdn2.unrealengine.com/Fortnite/fortnite-game/battleroyalenews/BR07_News_Tile_Creative-512x512-512x512-7890123456789012345678901234567890123456789a.jpg',
                'hidden': False,
                'messageType': 'normal',
                '_type': 'CommonUI Simple Message MOTD',
                'title': 'Creative Mode Available',
                'body': 'Build, play, and share your own island creations! Creative mode gives you the tools to make your own Fortnite experience.',
                'videoString': '',
                'tabTitleOverride': 'Creative',
                'buttonTextOverride': 'Create',
                'sortingPriority': 7,
                'id': 'season7-creative-mode'
            }
        ]
        
        # Select news based on hour for rotation (changes every 6 hours)
        selected_news = news_rotation[(current_hour // 6) % len(news_rotation)]
        
        # Dynamic backgrounds for Season 7 (winter theme)
        season7_backgrounds = [
            {
                'stage': 'winter',
                'key': 'lobby_winter_morning',
                'backgroundimage': 'https://cdn2.unrealengine.com/Fortnite/fortnite-game/backgrounds/Season7_Lobby_Winter_Morning-1920x1080.jpg'
            },
            {
                'stage': 'winter',
                'key': 'lobby_winter_evening', 
                'backgroundimage': 'https://cdn2.unrealengine.com/Fortnite/fortnite-game/backgrounds/Season7_Lobby_Winter_Evening-1920x1080.jpg'
            },
            {
                'stage': 'winter',
                'key': 'lobby_ice_storm',
                'backgroundimage': 'https://cdn2.unrealengine.com/Fortnite/fortnite-game/backgrounds/Season7_Lobby_IceStorm-1920x1080.jpg'
            }
        ]
        
        # Select background based on time of day
        if 6 <= current_hour < 18:
            selected_bg = season7_backgrounds[0]  # Morning
        elif 18 <= current_hour < 22:
            selected_bg = season7_backgrounds[1]  # Evening
        else:
            selected_bg = season7_backgrounds[2]  # Night/Ice Storm
        
        content_data = {
            'jcr:isCheckedOut': True,
            '_title': 'Fortnite Game',
            'jcr:baseVersion': 'a7ca237317f1e74f9b23aa4d-1234567890123',
            '_activeDate': '2018-12-06T14:00:00.000Z',
            'lastModified': datetime.utcnow().isoformat() + 'Z',
            '_locale': 'en-US',
            'battleroyalenewsv2': {
                'news': {
                    'motds': [
                        selected_news,
                        {
                            'entryType': 'Text',
                            'image': 'https://cdn2.unrealengine.com/Fortnite/fortnite-game/battleroyalenews/BR07_News_Featured_Emulator-1920x1080-1920x1080-emulator123456789012345678901234567890.jpg',
                            'tileImage': 'https://cdn2.unrealengine.com/Fortnite/fortnite-game/battleroyalenews/BR07_News_Tile_Emulator-512x512-512x512-emulator567890123456789012345678901234.jpg',
                            'hidden': False,
                            'messageType': 'normal',
                            '_type': 'CommonUI Simple Message MOTD',
                            'title': 'Season 7.40 Emulator',
                            'body': 'Welcome to the Fortnite Season 7.40 Emulator! Experience the winter wonderland with all features unlocked.',
                            'videoString': '',
                            'tabTitleOverride': 'Emulator',
                            'buttonTextOverride': 'Learn More',
                            'sortingPriority': 5,
                            'id': 'emulator-welcome'
                        }
                    ]
                }
            },
            'emergencynotice': {
                'news': {
                    'platform_messages': [
                        {
                            'hidden': False,
                            'messageType': 'normal',
                            '_type': 'CommonUI Simple Message Base',
                            'title': 'Server Status',
                            'body': 'All systems operational. Enjoy Season 7!',
                            'spotlight': False
                        }
                    ],
                    'emergency_notices': [
                        {
                            'hidden': False,
                            'messageType': 'normal',
                            '_type': 'CommonUI Simple Message Base',
                            'title': 'Ice Storm Event Active',
                            'body': 'The Ice King\'s storm is affecting the island. Expect frozen areas and new gameplay mechanics!',
                            'spotlight': True
                        }
                    ]
                }
            },
            'dynamicbackgrounds': {
                'backgrounds': {
                    'backgrounds': [selected_bg],
                    'colorscheme': 'Winter'
                }
            },
            'shopSections': {
                'sectionList': {
                    'sections': [
                        {
                            'bSortOffersByOwnership': False,
                            'bShowIneligibleOffersIfGiftable': False,
                            'bEnableToastNotification': True,
                            'background': {
                                'stage': 'winter',
                                'key': 'shop_winter_bg'
                            },
                            'sectionId': 'Featured',
                            'sectionDisplayName': 'Featured',
                            'landingPriority': 65
                        },
                        {
                            'bSortOffersByOwnership': False,
                            'bShowIneligibleOffersIfGiftable': False,
                            'bEnableToastNotification': True,
                            'background': {
                                'stage': 'winter',
                                'key': 'shop_daily_bg'
                            },
                            'sectionId': 'Daily',
                            'sectionDisplayName': 'Daily Items',
                            'landingPriority': 64
                        }
                    ]
                }
            }
        }
        return web.json_response(content_data)
    
    async def version_check(self, request):
        """Version check - bypass update requirements"""
        platform = request.match_info.get('platform', 'Windows')
        version_data = {
            'type': 'NO_UPDATE'
        }
        return web.json_response(version_data)
    
    async def version_check_legacy(self, request):
        """Legacy version check endpoint"""
        return web.json_response({
            'type': 'NO_UPDATE'
        })
    
    async def get_content_pages_region(self, request):
        """Get content pages for specific region"""
        region = request.match_info['region']
        return await self.get_content_pages(request)
    
    async def get_distribution_points(self, request):
        """Get distribution points"""
        return web.json_response({
            'distributions': ['https://localhost:443']
        })
    
    async def get_assets(self, request):
        """Get platform assets"""
        return web.json_response({
            'elements': [],
            'paging': {},
            'totalElements': 0
        })
    
    async def lightswitch_status(self, request):
        """Lightswitch bulk status - enable all services"""
        services = [
            'fortnite', 'launcher', 'Fortnite', 'eulatracking',
            'datarouter', 'account', 'friends'
        ]
        
        status_data = []
        for service in services:
            status_data.append({
                'serviceInstanceId': service,
                'status': 'UP',
                'message': 'Service is operational',
                'maintenanceUri': None,
                'overrideCatalogIds': [],
                'allowedActions': ['PLAY', 'DOWNLOAD'],
                'banned': False,
                'launcherInfoDTO': {
                    'appName': 'Fortnite',
                    'catalogItemId': '4fe75bbc5a674f4f9b356b5c90567da5',
                    'namespace': 'fn'
                }
            })
        
        return web.json_response(status_data)
    
    async def fortnite_status(self, request):
        """Fortnite service status"""
        return web.json_response({
            'serviceInstanceId': 'fortnite',
            'status': 'UP',
            'message': 'Fortnite is online',
            'maintenanceUri': None,
            'overrideCatalogIds': [],
            'allowedActions': ['PLAY', 'DOWNLOAD'],
            'banned': False,
            'launcherInfoDTO': {
                'appName': 'Fortnite',
                'catalogItemId': '4fe75bbc5a674f4f9b356b5c90567da5',
                'namespace': 'fn'
            }
        })
    
    async def service_status(self, request):
        """Generic service status"""
        service_id = request.match_info['service_id']
        return web.json_response({
            'serviceInstanceId': service_id,
            'status': 'UP',
            'message': f'{service_id} is online',
            'maintenanceUri': None,
            'overrideCatalogIds': [],
            'allowedActions': ['PLAY', 'DOWNLOAD'],
            'banned': False
        })
    
    async def persona_lookup(self, request):
        """Persona account lookup"""
        q = request.query.get('q', '')
        accounts = []
        
        # Search through stored accounts
        for account_id, account in self.accounts.items():
            if q.lower() in account.get('displayName', '').lower():
                accounts.append({
                    'accountId': account_id,
                    'displayName': account.get('displayName', 'FortnitePlayer')
                })
        
        return web.json_response(accounts)
    
    async def eula_tracking(self, request):
        """EULA tracking endpoint"""
        account_id = request.match_info['account_id']
        return web.json_response([])
    
    async def datarouter_data(self, request):
        """Datarouter data collection"""
        # Accept any data but don't process it
        return web.Response(status=204)
    
    def load_battle_pass_config(self):
        """Load Season 7 Battle Pass configuration"""
        try:
            with open('config/Season7.json', 'r') as f:
                self.battle_pass_config = json.load(f)
            self.logger.info("Season 7 Battle Pass configuration loaded")
        except FileNotFoundError:
            self.logger.error("Season7.json not found, battle pass features disabled")
            self.battle_pass_config = None
        except json.JSONDecodeError as e:
            self.logger.error(f"Invalid Season7.json format: {e}")
            self.battle_pass_config = None
    
    async def unlock_battle_pass(self, request):
        """Unlock Battle Pass for user"""
        account_id = request.match_info['account_id']
        
        # Get user from database
        user = self.db.get_user(account_id)
        if not user:
            self.db.create_user(account_id, f'Player_{account_id[:8]}', f'{account_id}@fortnite.local')
            user = self.db.get_user(account_id)
        
        # Check if user has enough V-Bucks
        battle_pass_price = 950  # Season 7 Battle Pass price
        if user['vbucks'] < battle_pass_price:
            return web.json_response({
                'error': 'insufficient_funds',
                'message': f'Need {battle_pass_price} V-Bucks to purchase Battle Pass'
            }, status=400)
        
        # Purchase Battle Pass
        import sqlite3
        conn = sqlite3.connect(self.db.db_path)
        cursor = conn.cursor()
        
        # Deduct V-Bucks and unlock Battle Pass
        cursor.execute('''
            UPDATE users 
            SET vbucks = vbucks - ?, battle_pass_purchased = TRUE
            WHERE account_id = ?
        ''', (battle_pass_price, account_id))
        
        conn.commit()
        conn.close()
        
        # Grant Battle Pass tier 1 rewards
        if self.battle_pass_config:
            tier_1_rewards = [tier for tier in self.battle_pass_config['tiers'] if tier['tier'] == 1]
            if tier_1_rewards:
                tier_1 = tier_1_rewards[0]
                if 'paidReward' in tier_1:
                    reward = tier_1['paidReward']
                    if reward['type'] == 'Currency':
                        # Grant V-Bucks
                        cursor = sqlite3.connect(self.db.db_path).cursor()
                        cursor.execute('UPDATE users SET vbucks = vbucks + ? WHERE account_id = ?', 
                                     (reward['quantity'], account_id))
                        cursor.connection.commit()
                        cursor.connection.close()
                    else:
                        # Grant item
                        self.db.grant_item(account_id, reward['templateId'], 1)
        
        # Return MCP-style response
        profile_changes = [{
            'changeType': 'statModified',
            'name': 'book_purchased',
            'value': True
        }]
        
        return web.json_response({
            'profileRevision': 2,
            'profileId': 'athena',
            'profileChangesBaseRevision': 1,
            'profileChanges': profile_changes,
            'profileCommandRevision': 2,
            'serverTime': datetime.utcnow().isoformat() + 'Z',
            'responseVersion': 1
        })
    
    async def get_battle_pass_info(self, request):
        """Get Battle Pass information for a season"""
        season = request.match_info.get('season', '7')
        
        if not self.battle_pass_config or str(self.battle_pass_config['seasonNumber']) != season:
            return web.json_response({'error': 'season_not_found'}, status=404)
        
        # Return Battle Pass configuration
        return web.json_response({
            'seasonNumber': self.battle_pass_config['seasonNumber'],
            'seasonName': self.battle_pass_config['seasonName'],
            'battlePassName': self.battle_pass_config['battlePassName'],
            'startDate': self.battle_pass_config['startDate'],
            'endDate': self.battle_pass_config['endDate'],
            'maxTier': self.battle_pass_config['maxTier'],
            'battlePassPrice': self.battle_pass_config['battlePassPrice'],
            'tierBundlePrice': self.battle_pass_config['tierBundlePrice'],
            'tiers': self.battle_pass_config['tiers'][:10],  # Return first 10 tiers for preview
            'challenges': self.battle_pass_config.get('challenges', [])
        })
    
    async def get_system_cloudstorage(self, request):
        """Get system cloud storage files list"""
        # Essential system files for Season 7.40 including encryption keys
        system_files = [
            {
                'uniqueFilename': 'ClientSettings.Sav',
                'filename': 'ClientSettings.Sav',
                'hash': '603E6907398C7E74E25C0AE8EC3A03FFAC7C9BB4',
                'hash256': 'A1B2C3D4E5F6789012345678901234567890ABCDEF1234567890ABCDEF123456',
                'length': 1024,
                'contentType': 'application/octet-stream',
                'uploaded': '2018-12-06T14:00:00.000Z',
                'storageType': 'S3',
                'doNotCache': False
            },
            {
                'uniqueFilename': 'DefaultGame.ini',
                'filename': 'DefaultGame.ini',
                'hash': '789ABC123DEF456789012345678901234567890A',
                'hash256': 'B2C3D4E5F6789012345678901234567890ABCDEF1234567890ABCDEF1234567A',
                'length': 2048,
                'contentType': 'text/plain',
                'uploaded': '2018-12-06T14:00:00.000Z',
                'storageType': 'S3',
                'doNotCache': False
            },
            {
                'uniqueFilename': 'PakEncryptionKeys.txt',
                'filename': 'PakEncryptionKeys.txt',
                'encryption_keys': '''# Fortnite Season 7.40 Pak Encryption Keys
# Main Key: 0xF2A0859F249BC9A511B3A8766420C6E943004CF0EAEE5B7CFFDB8F10953E994F
# Dynamic Keys with specific content sets
pakchunk0-WindowsClient.pak:0xF2A0859F249BC9A511B3A8766420C6E943004CF0EAEE5B7CFFDB8F10953E994F
pakchunk0_s1-WindowsClient.pak:0xF2A0859F249BC9A511B3A8766420C6E943004CF0EAEE5B7CFFDB8F10953E994F
pakchunk0_s2-WindowsClient.pak:0xF2A0859F249BC9A511B3A8766420C6E943004CF0EAEE5B7CFFDB8F10953E994F
pakchunk0_s3-WindowsClient.pak:0xF2A0859F249BC9A511B3A8766420C6E943004CF0EAEE5B7CFFDB8F10953E994F
pakchunk0_s4-WindowsClient.pak:0xF2A0859F249BC9A511B3A8766420C6E943004CF0EAEE5B7CFFDB8F10953E994F
pakchunk0_s5-WindowsClient.pak:0xF2A0859F249BC9A511B3A8766420C6E943004CF0EAEE5B7CFFDB8F10953E994F
pakchunk0_s6-WindowsClient.pak:0xF2A0859F249BC9A511B3A8766420C6E943004CF0EAEE5B7CFFDB8F10953E994F
pakchunk0_s7-WindowsClient.pak:0xF2A0859F249BC9A511B3A8766420C6E943004CF0EAEE5B7CFFDB8F10953E994F
pakchunk1-WindowsClient.pak:0xF2A0859F249BC9A511B3A8766420C6E943004CF0EAEE5B7CFFDB8F10953E994F
pakchunk1_s1-WindowsClient.pak:0xF2A0859F249BC9A511B3A8766420C6E943004CF0EAEE5B7CFFDB8F10953E994F
pakchunk2-WindowsClient.pak:0xF2A0859F249BC9A511B3A8766420C6E943004CF0EAEE5B7CFFDB8F10953E994F
pakchunk5-WindowsClient.pak:0xF2A0859F249BC9A511B3A8766420C6E943004CF0EAEE5B7CFFDB8F10953E994F
pakchunk7-WindowsClient.pak:0xF2A0859F249BC9A511B3A8766420C6E943004CF0EAEE5B7CFFDB8F10953E994F
pakchunk8-WindowsClient.pak:0xF2A0859F249BC9A511B3A8766420C6E943004CF0EAEE5B7CFFDB8F10953E994F
pakchunk9-WindowsClient.pak:0xF2A0859F249BC9A511B3A8766420C6E943004CF0EAEE5B7CFFDB8F10953E994F
pakchunk1000-WindowsClient.pak:0x121D529E48141A7E5D0F278BF4559F22
pakchunk1001-WindowsClient.pak:0x558C4703445945BA01B8A4A7F5AEEC5E
pakchunk1002-WindowsClient.pak:0x8A29D48D47F92655750C38908C8DD218
pakchunk1003-WindowsClient.pak:0x6211F2C4803E46EDF7AF7A538625AA28D61DBC36CBD39C974B129AAD1B8C4B1C91C415954BF27B6E43970FB8A75FE8BB
pakchunk1004-WindowsClient.pak:0xB9162E973436CDD186F548AC430DB033D38E33FF49B12585C05B7977FDE89278D776CA2A40FD9EC1F8522E9E13E99031
''',
                'length': 512,
                'contentType': 'text/plain',
                'uploaded': '2018-12-06T14:00:00.000Z',
                'storageType': 'S3',
                'doNotCache': False
            },
            {
                'uniqueFilename': 'LootQuotaData.json',
                'filename': 'LootQuotaData.json',
                'hash': 'F8G9H0I1J2K3L4M5678901BCDEF234567890123',
                'hash256': 'D4E5F6G789012345678901234567890BCDEF1234567890BCDEF123456789C',
                'length': 256,
                'contentType': 'application/json',
                'uploaded': '2018-12-06T14:00:00.000Z',
                'storageType': 'S3',
                'doNotCache': False
            }
        ]
        
        return web.json_response(system_files)
    
    async def get_system_file(self, request):
        """Get specific system cloud storage file"""
        filename = request.match_info['filename']
        
        if filename == 'ClientSettings.Sav':
            # Return minimal client settings for Season 7.40
            settings_data = b'\x00\x01\x02\x03' + b'\x00' * 1020  # Mock binary data
            return web.Response(body=settings_data, content_type='application/octet-stream')
        elif filename == 'DefaultGame.ini':
            # Return basic game configuration
            config_data = '''[/Script/FortniteGame.FortGameInstance]
!NetDriverDefinitions=ClearArray
+NetDriverDefinitions=(DefName="GameNetDriver",DriverClassName="OnlineSubsystemSteam.SteamNetDriver",DriverClassNameFallback="OnlineSubsystemUtils.IpNetDriver")

[/Script/OnlineSubsystemUtils.IpNetDriver]
NetConnectionClassName="OnlineSubsystemUtils.IpConnection"

[/Script/FortniteGame.FortPlayerController]
bShowMobileHUD=False
'''
            return web.Response(text=config_data, content_type='text/plain')
        elif filename == 'PakEncryptionKeys.txt':
            # Return encryption keys for Season 7.40 pak files
            encryption_keys = '''# Fortnite Season 7.40 Pak Encryption Keys
# Main Key: 0xF2A0859F249BC9A511B3A8766420C6E943004CF0EAEE5B7CFFDB8F10953E994F
# Dynamic Keys with specific content sets
pakchunk0-WindowsClient.pak:0xF2A0859F249BC9A511B3A8766420C6E943004CF0EAEE5B7CFFDB8F10953E994F
pakchunk0_s1-WindowsClient.pak:0xF2A0859F249BC9A511B3A8766420C6E943004CF0EAEE5B7CFFDB8F10953E994F
pakchunk0_s2-WindowsClient.pak:0xF2A0859F249BC9A511B3A8766420C6E943004CF0EAEE5B7CFFDB8F10953E994F
pakchunk0_s3-WindowsClient.pak:0xF2A0859F249BC9A511B3A8766420C6E943004CF0EAEE5B7CFFDB8F10953E994F
pakchunk0_s4-WindowsClient.pak:0xF2A0859F249BC9A511B3A8766420C6E943004CF0EAEE5B7CFFDB8F10953E994F
pakchunk0_s5-WindowsClient.pak:0xF2A0859F249BC9A511B3A8766420C6E943004CF0EAEE5B7CFFDB8F10953E994F
pakchunk0_s6-WindowsClient.pak:0xF2A0859F249BC9A511B3A8766420C6E943004CF0EAEE5B7CFFDB8F10953E994F
pakchunk0_s7-WindowsClient.pak:0xF2A0859F249BC9A511B3A8766420C6E943004CF0EAEE5B7CFFDB8F10953E994F
pakchunk1-WindowsClient.pak:0xF2A0859F249BC9A511B3A8766420C6E943004CF0EAEE5B7CFFDB8F10953E994F
pakchunk1_s1-WindowsClient.pak:0xF2A0859F249BC9A511B3A8766420C6E943004CF0EAEE5B7CFFDB8F10953E994F
pakchunk2-WindowsClient.pak:0xF2A0859F249BC9A511B3A8766420C6E943004CF0EAEE5B7CFFDB8F10953E994F
pakchunk5-WindowsClient.pak:0xF2A0859F249BC9A511B3A8766420C6E943004CF0EAEE5B7CFFDB8F10953E994F
pakchunk7-WindowsClient.pak:0xF2A0859F249BC9A511B3A8766420C6E943004CF0EAEE5B7CFFDB8F10953E994F
pakchunk8-WindowsClient.pak:0xF2A0859F249BC9A511B3A8766420C6E943004CF0EAEE5B7CFFDB8F10953E994F
pakchunk9-WindowsClient.pak:0xF2A0859F249BC9A511B3A8766420C6E943004CF0EAEE5B7CFFDB8F10953E994F
pakchunk1000-WindowsClient.pak:0x121D529E48141A7E5D0F278BF4559F22
pakchunk1001-WindowsClient.pak:0x558C4703445945BA01B8A4A7F5AEEC5E
pakchunk1002-WindowsClient.pak:0x8A29D48D47F92655750C38908C8DD218
pakchunk1003-WindowsClient.pak:0x6211F2C4803E46EDF7AF7A538625AA28D61DBC36CBD39C974B129AAD1B8C4B1C91C415954BF27B6E43970FB8A75FE8BB
pakchunk1004-WindowsClient.pak:0xB9162E973436CDD186F548AC430DB033D38E33FF49B12585C05B7977FDE89278D776CA2A40FD9EC1F8522E9E13E99031
'''
            return web.Response(text=encryption_keys, content_type='text/plain')
        elif filename == 'LootQuotaData.json':
            # Return loot quota data for Season 7.40
            loot_quota_data = '''{
    "LootQuotas": {
        "Common": 0.6,
        "Uncommon": 0.25,
        "Rare": 0.12,
        "Epic": 0.025,
        "Legendary": 0.005
    },
    "WeaponQuotas": {
        "AssaultRifle": 0.3,
        "Shotgun": 0.25,
        "SMG": 0.2,
        "Sniper": 0.15,
        "Pistol": 0.1
    },
    "Season": 7,
    "Version": "7.40"
}'''
            return web.Response(text=loot_quota_data, content_type='application/json')
        
        return web.Response(status=404)
    
    async def get_user_cloudstorage(self, request):
        """Get user cloud storage files list"""
        account_id = request.match_info['account_id']
        
        # Mock user files - in real implementation, this would come from database
        user_files = [
            {
                'uniqueFilename': f'{account_id}_UserSettings.Sav',
                'filename': 'UserSettings.Sav',
                'hash': f'{account_id[:8]}1234567890ABCDEF1234567890ABCDEF12345678',
                'hash256': f'{account_id[:16]}34567890ABCDEF1234567890ABCDEF1234567890ABCDEF123456',
                'length': 512,
                'contentType': 'application/octet-stream',
                'uploaded': datetime.utcnow().isoformat() + 'Z',
                'storageType': 'S3',
                'doNotCache': True
            },
            {
                'uniqueFilename': f'{account_id}_GameUserSettings.ini',
                'filename': 'GameUserSettings.ini',
                'hash': f'{account_id[:8]}ABCDEF1234567890ABCDEF1234567890ABCDEF12',
                'hash256': f'{account_id[:16]}567890ABCDEF1234567890ABCDEF1234567890ABCDEF1234567',
                'length': 1536,
                'contentType': 'text/plain',
                'uploaded': datetime.utcnow().isoformat() + 'Z',
                'storageType': 'S3',
                'doNotCache': True
            }
        ]
        
        return web.json_response(user_files)
    
    async def get_user_file(self, request):
        """Get specific user cloud storage file"""
        account_id = request.match_info['account_id']
        filename = request.match_info['filename']
        
        if filename == 'UserSettings.Sav':
            # Return user-specific settings
            user_settings = b'\x01\x02\x03\x04' + b'\x00' * 508  # Mock binary data
            return web.Response(body=user_settings, content_type='application/octet-stream')
        elif filename == 'GameUserSettings.ini':
            # Return user game settings
            user_config = f'''[/Script/FortniteGame.FortGameUserSettings]
LastConfirmedFullscreenMode=1
PreferredFullscreenMode=1
ResolutionSizeX=1920
ResolutionSizeY=1080
LastUserConfirmedResolutionSizeX=1920
LastUserConfirmedResolutionSizeY=1080
WindowPosX=-1
WindowPosY=-1
FullscreenMode=1
LastConfirmedFullscreenMode=1
PreferredFullscreenMode=1
Version=5
AudioQualityLevel=1
LastConfirmedAudioQualityLevel=1
FrameRateLimit=0.000000
DesiredScreenWidth=1920
DesiredScreenHeight=1080
LastUserConfirmedDesiredScreenWidth=1920
LastUserConfirmedDesiredScreenHeight=1080
bUseDesiredScreenHeight=False
AccountId={account_id}
'''
            return web.Response(text=user_config, content_type='text/plain')
        
        return web.Response(status=404)
    
    async def put_user_file(self, request):
        """Upload/update user cloud storage file"""
        account_id = request.match_info['account_id']
        filename = request.match_info['filename']
        
        # Read the uploaded data
        data = await request.read()
        
        # In a real implementation, you would save this to storage
        # For now, just acknowledge the upload
        self.logger.info(f"User {account_id} uploaded {filename} ({len(data)} bytes)")
        
        return web.Response(status=204)
    
    async def healthz(self, request):
        """Health check endpoint"""
        return web.json_response({'status': 'ok'})
    
    async def catch_all(self, request):
        """Catch-all handler for unknown endpoints"""
        path = request.path
        method = request.method
        
        self.logger.warning(f"Unknown endpoint: {method} {path}")
        
        # Return empty response for unknown endpoints
        return web.json_response({})
    
    def create_ssl_context(self):
        """Create SSL context for HTTPS"""
        try:
            ssl_context = ssl.create_default_context(ssl.Purpose.CLIENT_AUTH)
            ssl_context.check_hostname = False
            ssl_context.verify_mode = ssl.CERT_NONE
            
            # Set additional SSL options for better compatibility
            ssl_context.options |= ssl.OP_NO_SSLv2
            ssl_context.options |= ssl.OP_NO_SSLv3
            ssl_context.options |= ssl.OP_SINGLE_DH_USE
            ssl_context.options |= ssl.OP_SINGLE_ECDH_USE
            
            # Set cipher suites that libcurl commonly accepts
            ssl_context.set_ciphers('ECDHE+AESGCM:ECDHE+CHACHA20:DHE+AESGCM:DHE+CHACHA20:!aNULL:!MD5:!DSS')
            
            # Prioritize mitmproxy CA certificate if available
            mitm_ca_cert_path = Path.home() / '.mitmproxy' / 'mitmproxy-ca-cert.pem'
            if mitm_ca_cert_path.exists():
                ssl_context.load_verify_locations(str(mitm_ca_cert_path))
                self.logger.info(f"Loaded mitmproxy CA certificate from {mitm_ca_cert_path}")
            
            # Create proper certificate chain if we have Epic Games certificates
            if os.path.exists('ssl/end-entity.crt') and os.path.exists('ssl/root-ca.crt') and os.path.exists('ssl/end-entity.key'):
                self.create_certificate_chain()
                ssl_context.load_cert_chain('ssl/server.crt', 'ssl/end-entity.key')
                self.logger.info("SSL certificate chain loaded (end-entity + Epic Root CA)")
                return ssl_context
            
            # Try to load SSL certificates - prioritize certificate chain
            cert_files = [
                ('ssl/end-entity.crt', 'ssl/end-entity.key'),  # New certificate chain
                ('ssl/windows-server.crt', 'ssl/windows-server.key'),  # Windows-compatible
                ('ssl/localhost.crt', 'ssl/localhost.key'),  # Localhost-specific
                ('ssl/server.crt', 'ssl/server.key')  # Fallback to original
            ]
            
            cert_loaded = False
            for cert_file, key_file in cert_files:
                if os.path.exists(cert_file) and os.path.exists(key_file):
                    ssl_context.load_cert_chain(cert_file, key_file)
                    self.logger.info(f"SSL certificates loaded from {cert_file}")
                    cert_loaded = True
                    break
            
            if not cert_loaded:
                self.logger.warning("No SSL certificates found, generating self-signed")
                self.generate_ssl_certificates()
                ssl_context.load_cert_chain('ssl/server.crt', 'ssl/server.key')
            
            return ssl_context
            
        except Exception as e:
            self.logger.error(f"SSL context creation failed: {str(e)}")
            return None
    
    def create_certificate_chain(self):
        """Create proper certificate chain by concatenating end-entity cert with Epic Root CA"""
        try:
            # Read the end-entity certificate
            with open('ssl/end-entity.crt', 'r') as f:
                end_entity_cert = f.read()
            
            # Read the Epic Games Root CA certificate
            with open('ssl/root-ca.crt', 'r') as f:
                root_ca_cert = f.read()
            
            # Concatenate certificates: end-entity first, then root CA
            certificate_chain = end_entity_cert.strip() + '\n' + root_ca_cert.strip() + '\n'
            
            # Write the certificate chain to server.crt
            with open('ssl/server.crt', 'w') as f:
                f.write(certificate_chain)
            
            self.logger.info("Certificate chain created: end-entity + Epic Root CA -> server.crt")
            
        except Exception as e:
            self.logger.error(f"Failed to create certificate chain: {str(e)}")
    
    def generate_ssl_certificates(self):
        """Generate self-signed SSL certificates"""
        try:
            from cryptography import x509
            from cryptography.x509.oid import NameOID, ExtensionOID
            from cryptography.hazmat.primitives import hashes, serialization
            from cryptography.hazmat.primitives.asymmetric import rsa
            import datetime
            import ipaddress
            
            # Generate private key with stronger parameters
            private_key = rsa.generate_private_key(
                public_exponent=65537,
                key_size=4096,  # Stronger key size
            )
            
            # Generate certificate
            subject = issuer = x509.Name([
                x509.NameAttribute(NameOID.COUNTRY_NAME, "US"),
                x509.NameAttribute(NameOID.STATE_OR_PROVINCE_NAME, "CA"),
                x509.NameAttribute(NameOID.LOCALITY_NAME, "San Francisco"),
                x509.NameAttribute(NameOID.ORGANIZATION_NAME, "Epic Games"),
                x509.NameAttribute(NameOID.COMMON_NAME, "*.ol.epicgames.com"),
            ])
            
            cert = x509.CertificateBuilder().subject_name(
                subject
            ).issuer_name(
                issuer
            ).public_key(
                private_key.public_key()
            ).serial_number(
                x509.random_serial_number()
            ).not_valid_before(
                datetime.datetime.utcnow()
            ).not_valid_after(
                datetime.datetime.utcnow() + datetime.timedelta(days=365)
            ).add_extension(
                x509.SubjectAlternativeName([
                    x509.DNSName("localhost"),
                    x509.DNSName("127.0.0.1"),
                    x509.DNSName("*.ol.epicgames.com"),
                    x509.DNSName("*.epicgames.com"),
                    x509.DNSName("datarouter.ol.epicgames.com"),
                    x509.DNSName("account-public-service-prod.ol.epicgames.com"),
                    x509.DNSName("fortnite-public-service-prod11.ol.epicgames.com"),
                    x509.IPAddress(ipaddress.IPv4Address("127.0.0.1")),
                    x509.DNSName("fortnite-public-service-prod10.ol.epicgames.com"),
                    x509.DNSName("fortnite-public-service-prod08.ol.epicgames.com"),
                    
                    # Content pages
                    x509.DNSName("content-public-service-prod.ol.epicgames.com"),
                    
                    # Lightswitch (service status)
                    x509.DNSName("lightswitch-public-service-prod.ol.epicgames.com"),
                    
                    # Launcher / assets
                    x509.DNSName("launcher-public-service-prod06.ol.epicgames.com"),
                    
                    # Persona
                    x509.DNSName("persona-public-service-prod.ol.epicgames.com"),
                    
                    # EULA tracking
                    x509.DNSName("eulatracking-public-service-prod06.ol.epicgames.com"),
                    
                    # Friends
                    x509.DNSName("friends-public-service-prod06.ol.epicgames.com"),
                    x509.DNSName("friends-public-service-prod.ol.epicgames.com"),
                    
                    # Events/Stats (older builds may touch these)
                    x509.DNSName("events-public-service-live.ol.epicgames.com"),
                    x509.DNSName("events-public-service-prod.ol.epicgames.com"),
                    x509.DNSName("statsproxy-public-service-live.ol.epicgames.com"),
                    
                    # Telemetry - Critical for login flow
                    x509.DNSName("datarouter.ol.epicgames.com"),
                ]),
                critical=False,
            ).add_extension(
                x509.KeyUsage(
                    digital_signature=True,
                    key_encipherment=True,
                    data_encipherment=True,
                    key_agreement=True,
                    content_commitment=True,
                    key_cert_sign=False,
                    crl_sign=False,
                    encipher_only=False,
                    decipher_only=False
                ),
                critical=True,
            ).add_extension(
                x509.BasicConstraints(ca=False, path_length=None),
                critical=True,
            ).add_extension(
                x509.ExtendedKeyUsage([
                    x509.oid.ExtendedKeyUsageOID.SERVER_AUTH,
                    x509.oid.ExtendedKeyUsageOID.CLIENT_AUTH,
                ]),
                critical=False,
            ).sign(private_key, hashes.SHA256())
            
            # Write certificate and key
            os.makedirs('ssl', exist_ok=True)
            
            with open('ssl/server.crt', 'wb') as f:
                f.write(cert.public_bytes(serialization.Encoding.PEM))
            
            with open('ssl/server.key', 'wb') as f:
                f.write(private_key.private_bytes(
                    encoding=serialization.Encoding.PEM,
                    format=serialization.PrivateFormat.PKCS8,
                    encryption_algorithm=serialization.NoEncryption()
                ))
            
            self.logger.info("Self-signed SSL certificates generated")
            
        except ImportError:
            self.logger.error("cryptography library not available for SSL generation")
        except Exception as e:
            self.logger.error(f"SSL certificate generation failed: {str(e)}")
    
    async def start_server(self):
        """Start the backend server"""
        try:
            # Create SSL context
            ssl_context = self.create_ssl_context()
            
            # Start server on port 443 (HTTPS)
            runner = web.AppRunner(self.app)
            await runner.setup()
            
            site = web.TCPSite(runner, '0.0.0.0', 8443, ssl_context=ssl_context)
            await site.start()
            
            self.logger.info("Backend server started on https://localhost:8443")
            
            # Also start HTTP redirect server on port 80
            try:
                http_app = web.Application()
                http_app.router.add_route('*', '/{path:.*}', self.http_redirect_handler)
                
                http_runner = web.AppRunner(http_app)
                await http_runner.setup()
                
                http_site = web.TCPSite(http_runner, '0.0.0.0', 80)
                await http_site.start()
                
                self.logger.info("HTTP redirect server started on http://localhost:80")
            except Exception as e:
                self.logger.warning(f"Could not start HTTP redirect server: {e}")
                
            # Keep server running
            while True:
                await asyncio.sleep(1)
                
        except Exception as e:
            self.logger.error(f"Server startup failed: {str(e)}")
            raise
                
    async def http_redirect_handler(self, request):
        """Redirect HTTP requests to HTTPS"""
        # For debugging, we can also handle HTTP requests directly
        # This helps with clients that might try HTTP first
        https_url = f"https://localhost:443{request.path_qs}"
        return web.Response(status=301, headers={'Location': https_url})

def main():
    """Main entry point"""
    backend = FortniteBackend()
    
    try:
        asyncio.run(backend.start_server())
    except KeyboardInterrupt:
        print("\nServer stopped by user")
    except Exception as e:
        print(f"Server error: {str(e)}")

if __name__ == "__main__":
    main()