import sqlite3
from pymongo import MongoClient
from werkzeug.security import generate_password_hash
import pyotp

# SQLite connection
sqlite_conn = sqlite3.connect('rbac.db')
sqlite_conn.row_factory = sqlite3.Row
sqlite_cursor = sqlite_conn.cursor()

# MongoDB connection
mongo_client = MongoClient('mongodb://localhost:27017/')
mongo_db = mongo_client['rbac_db']

def migrate_users():
    sqlite_cursor.execute('SELECT * FROM users')
    users = sqlite_cursor.fetchall()
    
    for user in users:
        mongo_db.users.insert_one({
            'username': user['username'],
            'password': user['password'],
            'role': user['role'],
            'totp_secret': user['totp_secret'] if user['totp_secret'] else pyotp.random_base32()
        })
    
    print(f"Migrated {len(users)} users.")

def migrate_roles():
    sqlite_cursor.execute('SELECT * FROM roles')
    roles = sqlite_cursor.fetchall()
    
    for role in roles:
        mongo_db.roles.insert_one({
            'name': role['name']
        })
    
    print(f"Migrated {len(roles)} roles.")

def migrate_api_endpoints():
    sqlite_cursor.execute('SELECT * FROM api_endpoints')
    endpoints = sqlite_cursor.fetchall()
    
    for endpoint in endpoints:
        mongo_db.api_endpoints.insert_one({
            'name': endpoint['name'],
            'endpoint': endpoint['endpoint'],
            'method': endpoint['method'],
            'description': endpoint['description']
        })
    
    print(f"Migrated {len(endpoints)} API endpoints.")

def create_indexes():
    mongo_db.users.create_index('username', unique=True)
    mongo_db.api_endpoints.create_index('name', unique=True)
    mongo_db.api_endpoints.create_index('endpoint', unique=True)
    print("Created indexes.")

def main():
    # Drop existing collections in MongoDB to avoid duplicates
    mongo_db.users.drop()
    mongo_db.roles.drop()
    mongo_db.api_endpoints.drop()
    
    migrate_users()
    migrate_roles()
    migrate_api_endpoints()
    create_indexes()
    
    print("Migration completed successfully.")

if __name__ == '__main__':
    main()
    sqlite_conn.close()
    mongo_client.close()
