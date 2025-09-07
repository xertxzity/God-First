import sqlite3
import json
import uuid
from datetime import datetime
import os

class FortniteDatabase:
    def __init__(self, db_path='data/fortnite_emulator.db'):
        self.db_path = db_path
        self.init_database()
    
    def init_database(self):
        """Initialize database with required tables"""
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()
        
        # Users table
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS users (
                account_id TEXT PRIMARY KEY,
                display_name TEXT UNIQUE,
                email TEXT,
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                last_login TIMESTAMP,
                vbucks INTEGER DEFAULT 0,
                level INTEGER DEFAULT 1,
                xp INTEGER DEFAULT 0,
                battle_pass_tier INTEGER DEFAULT 1,
                battle_pass_purchased BOOLEAN DEFAULT FALSE,
                battle_pass_xp INTEGER DEFAULT 0
            )
        ''')
        
        # Profiles table (MCP profiles)
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS profiles (
                account_id TEXT,
                profile_id TEXT,
                profile_data TEXT,
                revision INTEGER DEFAULT 1,
                updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                PRIMARY KEY (account_id, profile_id),
                FOREIGN KEY (account_id) REFERENCES users (account_id)
            )
        ''')
        
        # Items table (cosmetics, weapons, etc.)
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS items (
                item_id TEXT PRIMARY KEY,
                template_id TEXT,
                name TEXT,
                description TEXT,
                rarity TEXT,
                type TEXT,
                season INTEGER,
                battle_pass_tier INTEGER,
                vbucks_price INTEGER,
                attributes TEXT
            )
        ''')
        
        # User items (inventory)
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS user_items (
                account_id TEXT,
                item_id TEXT,
                quantity INTEGER DEFAULT 1,
                attributes TEXT,
                acquired_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                PRIMARY KEY (account_id, item_id),
                FOREIGN KEY (account_id) REFERENCES users (account_id),
                FOREIGN KEY (item_id) REFERENCES items (item_id)
            )
        ''')
        
        # Locker loadouts
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS locker_loadouts (
                account_id TEXT,
                slot_type TEXT,
                item_id TEXT,
                variant_data TEXT,
                updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                PRIMARY KEY (account_id, slot_type),
                FOREIGN KEY (account_id) REFERENCES users (account_id)
            )
        ''')
        
        # Friends
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS friends (
                account_id TEXT,
                friend_id TEXT,
                status TEXT DEFAULT 'ACCEPTED',
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                PRIMARY KEY (account_id, friend_id),
                FOREIGN KEY (account_id) REFERENCES users (account_id),
                FOREIGN KEY (friend_id) REFERENCES users (account_id)
            )
        ''')
        
        # Stats
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS stats (
                account_id TEXT,
                stat_name TEXT,
                stat_value INTEGER DEFAULT 0,
                season INTEGER DEFAULT 7,
                updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                PRIMARY KEY (account_id, stat_name, season),
                FOREIGN KEY (account_id) REFERENCES users (account_id)
            )
        ''')
        
        # Item shop
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS shop_sections (
                section_id TEXT PRIMARY KEY,
                section_name TEXT,
                display_priority INTEGER DEFAULT 0,
                active BOOLEAN DEFAULT TRUE
            )
        ''')
        
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS shop_items (
                shop_item_id TEXT PRIMARY KEY,
                section_id TEXT,
                item_id TEXT,
                price INTEGER,
                currency TEXT DEFAULT 'MtxCurrency',
                start_date TIMESTAMP,
                end_date TIMESTAMP,
                display_priority INTEGER DEFAULT 0,
                FOREIGN KEY (section_id) REFERENCES shop_sections (section_id),
                FOREIGN KEY (item_id) REFERENCES items (item_id)
            )
        ''')
        
        conn.commit()
        conn.close()
        
        # Initialize default data
        self.init_default_data()
    
    def init_default_data(self):
        """Initialize default items and shop data for Season 7.40"""
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()
        
        # Check if default data already exists
        cursor.execute('SELECT COUNT(*) FROM items')
        if cursor.fetchone()[0] > 0:
            conn.close()
            return
        
        # Default Season 7.40 items
        default_items = [
            # Skins
            ('AthenaCharacter:CID_028_Athena_Commando_F', 'CID_028_Athena_Commando_F', 'Raven', 'Dark and mysterious', 'Epic', 'Outfit', 7, None, 2000),
            ('AthenaCharacter:CID_029_Athena_Commando_F_Halloween', 'CID_029_Athena_Commando_F_Halloween', 'Skull Trooper', 'Spooky scary skeleton', 'Epic', 'Outfit', 7, None, 1500),
            ('AthenaCharacter:CID_030_Athena_Commando_M_Halloween', 'CID_030_Athena_Commando_M_Halloween', 'Ghoul Trooper', 'Undead soldier', 'Epic', 'Outfit', 7, None, 1500),
            
            # Pickaxes
            ('AthenaPickaxe:Pickaxe_ID_015_Halloween', 'Pickaxe_ID_015_Halloween', 'Reaper', 'Harvest with style', 'Epic', 'Harvesting Tool', 7, None, 800),
            ('AthenaPickaxe:Pickaxe_ID_016_Scythe', 'Pickaxe_ID_016_Scythe', 'Scythe', 'Sharp and deadly', 'Rare', 'Harvesting Tool', 7, None, 800),
            
            # Gliders
            ('AthenaGlider:Glider_ID_003_Umbrella', 'Glider_ID_003_Umbrella', 'Umbrella', 'Victory Royale reward', 'Uncommon', 'Glider', 7, None, 0),
            ('AthenaGlider:Glider_ID_004_Stealth', 'Glider_ID_004_Stealth', 'Stealth', 'Silent descent', 'Rare', 'Glider', 7, None, 500),
            
            # Emotes
            ('AthenaDance:EID_DanceMoves', 'EID_DanceMoves', 'Dance Moves', 'Show off your moves', 'Rare', 'Emote', 7, None, 500),
            ('AthenaDance:EID_Floss', 'EID_Floss', 'Floss', 'Dental hygiene dance', 'Rare', 'Emote', 7, None, 500),
            
            # Battle Pass items
            ('AthenaCharacter:CID_035_Athena_Commando_M_Medieval', 'CID_035_Athena_Commando_M_Medieval', 'Black Knight', 'Legendary warrior', 'Legendary', 'Outfit', 7, 70, 0),
            ('AthenaPickaxe:Pickaxe_ID_020_Medieval', 'Pickaxe_ID_020_Medieval', 'Axecalibur', 'Legendary blade', 'Legendary', 'Harvesting Tool', 7, 65, 0),
        ]
        
        for item in default_items:
            cursor.execute('''
                INSERT OR IGNORE INTO items 
                (template_id, item_id, name, description, rarity, type, season, battle_pass_tier, vbucks_price, attributes)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            ''', (*item, '{}'))
        
        # Default shop sections
        shop_sections = [
            ('featured', 'Featured', 1),
            ('daily', 'Daily', 2),
            ('vbucks', 'V-Bucks', 3)
        ]
        
        for section in shop_sections:
            cursor.execute('INSERT OR IGNORE INTO shop_sections (section_id, section_name, display_priority) VALUES (?, ?, ?)', section)
        
        conn.commit()
        conn.close()
    
    def create_user(self, account_id, display_name, email=None):
        """Create a new user account"""
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()
        
        try:
            cursor.execute('''
                INSERT INTO users (account_id, display_name, email, vbucks, level, xp)
                VALUES (?, ?, ?, ?, ?, ?)
            ''', (account_id, display_name, email, 1000, 1, 0))  # Start with 1000 V-Bucks
            
            # Create default profiles
            self.create_default_profiles(account_id)
            
            conn.commit()
            return True
        except sqlite3.IntegrityError:
            return False
        finally:
            conn.close()
    
    def create_default_profiles(self, account_id):
        """Create default MCP profiles for a user"""
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()
        
        # Athena profile (BR)
        athena_profile = {
            'accountId': account_id,
            'profileId': 'athena',
            'version': 'fortnite_emulator_7.40',
            'items': {},
            'stats': {
                'attributes': {
                    'level': 1,
                    'xp': 0,
                    'accountLevel': 1,
                    'book_level': 1,
                    'book_xp': 0,
                    'book_purchased': False,
                    'lifetime_wins': 0,
                    'party_assist_quest': '',
                    'quest_manager': {},
                    'book_progress': {}
                }
            },
            'commandRevision': 1
        }
        
        # Common Core profile
        common_core_profile = {
            'accountId': account_id,
            'profileId': 'common_core',
            'version': 'fortnite_emulator_7.40',
            'items': {},
            'stats': {
                'attributes': {
                    'mtx_purchase_history': {},
                    'current_mtx_platform': 'EpicPC',
                    'mtx_affiliate_set_time': '2018-12-06T14:30:00.000Z',
                    'inventory_limit_bonus': 0,
                    'daily_rewards': {},
                    'competitive_identity': {},
                    'season_match_boost': 0,
                    'loadouts': []
                }
            },
            'commandRevision': 1
        }
        
        cursor.execute('''
            INSERT OR REPLACE INTO profiles (account_id, profile_id, profile_data, revision)
            VALUES (?, ?, ?, ?)
        ''', (account_id, 'athena', json.dumps(athena_profile), 1))
        
        cursor.execute('''
            INSERT OR REPLACE INTO profiles (account_id, profile_id, profile_data, revision)
            VALUES (?, ?, ?, ?)
        ''', (account_id, 'common_core', json.dumps(common_core_profile), 1))
        
        conn.commit()
        conn.close()
    
    def get_user(self, account_id):
        """Get user by account ID"""
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()
        
        cursor.execute('SELECT * FROM users WHERE account_id = ?', (account_id,))
        row = cursor.fetchone()
        conn.close()
        
        if row:
            return {
                'account_id': row[0],
                'display_name': row[1],
                'email': row[2],
                'created_at': row[3],
                'last_login': row[4],
                'vbucks': row[5],
                'level': row[6],
                'xp': row[7],
                'battle_pass_tier': row[8],
                'battle_pass_purchased': row[9],
                'battle_pass_xp': row[10]
            }
        return None
    
    def get_profile(self, account_id, profile_id):
        """Get MCP profile data"""
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()
        
        cursor.execute('SELECT profile_data, revision FROM profiles WHERE account_id = ? AND profile_id = ?', 
                      (account_id, profile_id))
        row = cursor.fetchone()
        conn.close()
        
        if row:
            profile_data = json.loads(row[0])
            profile_data['profileRevision'] = row[1]
            return profile_data
        return None
    
    def update_profile(self, account_id, profile_id, profile_data):
        """Update MCP profile data"""
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()
        
        # Increment revision
        cursor.execute('SELECT revision FROM profiles WHERE account_id = ? AND profile_id = ?', 
                      (account_id, profile_id))
        row = cursor.fetchone()
        new_revision = (row[0] + 1) if row else 1
        
        cursor.execute('''
            INSERT OR REPLACE INTO profiles (account_id, profile_id, profile_data, revision, updated_at)
            VALUES (?, ?, ?, ?, CURRENT_TIMESTAMP)
        ''', (account_id, profile_id, json.dumps(profile_data), new_revision))
        
        conn.commit()
        conn.close()
        
        return new_revision
    
    def get_user_items(self, account_id):
        """Get all items owned by user"""
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()
        
        cursor.execute('''
            SELECT ui.item_id, ui.quantity, ui.attributes, i.template_id, i.name, i.rarity, i.type
            FROM user_items ui
            JOIN items i ON ui.item_id = i.item_id
            WHERE ui.account_id = ?
        ''', (account_id,))
        
        items = {}
        for row in cursor.fetchall():
            items[row[0]] = {
                'templateId': row[3],
                'attributes': json.loads(row[2]) if row[2] else {},
                'quantity': row[1]
            }
        
        conn.close()
        return items
    
    def grant_item(self, account_id, item_id, quantity=1, attributes=None):
        """Grant an item to a user"""
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()
        
        attributes_json = json.dumps(attributes) if attributes else '{}'
        
        cursor.execute('''
            INSERT OR REPLACE INTO user_items (account_id, item_id, quantity, attributes)
            VALUES (?, ?, ?, ?)
        ''', (account_id, item_id, quantity, attributes_json))
        
        conn.commit()
        conn.close()
    
    def get_locker_loadout(self, account_id):
        """Get user's locker loadout"""
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()
        
        cursor.execute('SELECT slot_type, item_id, variant_data FROM locker_loadouts WHERE account_id = ?', 
                      (account_id,))
        
        loadout = {}
        for row in cursor.fetchall():
            loadout[row[0]] = {
                'item': row[1],
                'variants': json.loads(row[2]) if row[2] else []
            }
        
        conn.close()
        return loadout
    
    def update_locker_slot(self, account_id, slot_type, item_id, variants=None):
        """Update a locker slot"""
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()
        
        variant_data = json.dumps(variants) if variants else '[]'
        
        cursor.execute('''
            INSERT OR REPLACE INTO locker_loadouts (account_id, slot_type, item_id, variant_data, updated_at)
            VALUES (?, ?, ?, ?, CURRENT_TIMESTAMP)
        ''', (account_id, slot_type, item_id, variant_data))
        
        conn.commit()
        conn.close()
    
    def close(self):
        """Close database connection"""
        pass  # Using context managers, no persistent connection