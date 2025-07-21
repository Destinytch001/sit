from functools import wraps
import os
from datetime import datetime, timedelta, timezone
from flask import Flask, request, jsonify
from pymongo import MongoClient
from werkzeug.security import generate_password_hash, check_password_hash
from dotenv import load_dotenv
import re
from flask_cors import CORS
import jwt
from bson import ObjectId

# Load environment variables
load_dotenv()

# Initialize Flask app
app = Flask(__name__)
app.secret_key = os.environ.get('SECRET_KEY', 'fallback-secret')
app.config["MONGO_URI"] = os.environ.get("MONGO_URI")

# Nigeria is UTC+1 (West Africa Time)
WAT_OFFSET = timedelta(hours=1)

def get_wat_time():
    """Get current time in WAT (UTC+1)"""
    return datetime.now(timezone.utc) + WAT_OFFSET

# Import & initialize extensions
from extensions import init_extensions
init_extensions(app)

# Register Blueprints AFTER extensions are ready
from notifications import notifications_bp
app.register_blueprint(notifications_bp)

from resources import resources_bp  
app.register_blueprint(resources_bp)

# Enable CORS
origins = os.environ.get("ALLOWED_ORIGINS").split(",")
CORS(app,
     resources={r"/*": {"origins": origins}},
     supports_credentials=True,
     allow_headers="*",
     expose_headers="*",
     methods=["GET", "POST", "PUT", "DELETE", "OPTIONS"])

@app.before_request
def handle_options():
    if request.method == 'OPTIONS':
        return _build_cors_preflight_response()

def _build_cors_preflight_response():
    response = jsonify({'status': 'preflight'})
    origin = request.headers.get('Origin', '*')
    response.headers.add("Access-Control-Allow-Origin", origin)
    response.headers.add("Access-Control-Allow-Headers", request.headers.get(
        'Access-Control-Request-Headers', 'Content-Type, Authorization'))
    response.headers.add("Access-Control-Allow-Methods", request.headers.get(
        'Access-Control-Request-Method', 'GET, POST, PUT, DELETE, OPTIONS'))
    response.headers.add("Access-Control-Allow-Credentials", 'true')
    response.headers.add("Access-Control-Max-Age", "86400")
    return response

@app.after_request
def add_security_headers(response):
    response.headers['X-Content-Type-Options'] = 'nosniff'
    response.headers['X-Frame-Options'] = 'SAMEORIGIN'
    response.headers['X-XSS-Protection'] = '1; mode=block'
    response.headers['Strict-Transport-Security'] = 'max-age=31536000; includeSubDomains'
    response.headers['Content-Security-Policy'] = "default-src 'self'"
    return response

# JWT Config
JWT_SECRET = os.environ.get('JWT_SECRET')
JWT_ALGORITHM = 'HS256'
JWT_EXPIRATION = timedelta(hours=12)

# Status thresholds in minutes
STATUS_CONFIG = {
    'HEARTBEAT_INTERVAL': 1,
    'IDLE_THRESHOLD': 3,
    'OFFLINE_THRESHOLD': 5
}

try:
    mongo_uri = os.environ.get('MONGO_URI')
    client = MongoClient(mongo_uri, socketTimeoutMS=30000, retryWrites=True, appName="naits_app")
    db = client.get_database('naits_db')
    client.admin.command('ping')
    print("✅ MongoDB connection successful")

    # Collections
    users_collection = db.users
    announcements_collection = db.announcements
    notifications_collection = db.notifications
    user_notifications_collection = db.user_notifications

    # ✅ Initialize notifications module
    from notifications import init_notifications_module
    init_notifications_module(users_collection, notifications_collection, user_notifications_collection)

    # Indexes
    users_collection.create_index([('last_seen', -1)])
    users_collection.create_index([('status', 1)])
    users_collection.create_index([('department', 1), ('status', 1)])

    announcements_collection.create_index([("target.type", 1)])
    announcements_collection.create_index([("target.value", 1)])
    announcements_collection.create_index([("created_at", -1)])

    notifications_collection.create_index([("audience_type", 1)])
    notifications_collection.create_index([("audience_value", 1)])
    notifications_collection.create_index([("created_at", -1)])

    user_notifications_collection.create_index([("user_id", 1)])
    user_notifications_collection.create_index([("notification_id", 1)])
    user_notifications_collection.create_index([("read", 1)])
    user_notifications_collection.create_index([("dismissed", 1)])
    user_notifications_collection.create_index([("created_at", -1)])

except Exception as e:
    print("❌ MongoDB connection failed:", e)

def verify_token(token):
    try:
        payload = jwt.decode(token, JWT_SECRET, algorithms=[JWT_ALGORITHM])
        return payload
    except jwt.ExpiredSignatureError:
        raise Exception('Token expired')
    except jwt.InvalidTokenError:
        raise Exception('Invalid token')

def requires_auth(f):
    @wraps(f)
    def decorated(*args, **kwargs):
        token = request.headers.get('Authorization')
        if not token:
            return jsonify({'success': False, 'error': 'Authorization required'}), 401
        
        try:
            token = token.replace('Bearer ', '')
            payload = verify_token(token)
            request.user_id = payload['user_id']
        except Exception as e:
            return jsonify({'success': False, 'error': str(e)}), 401
        
        return f(*args, **kwargs)
    return decorated

def requires_admin(f):
    @wraps(f)
    def decorated(*args, **kwargs):
        token = request.headers.get('Authorization')
        if not token:
            return jsonify({'success': False, 'error': 'Authorization required'}), 401
        
        try:
            token = token.replace('Bearer ', '')
            payload = verify_token(token)
            user = users_collection.find_one({'_id': ObjectId(payload['user_id'])})
            
            if not user or user.get('role') != 'admin':
                return jsonify({'success': False, 'error': 'Admin access required'}), 403
                
            request.user = user
        except Exception as e:
            return jsonify({'success': False, 'error': str(e)}), 401
        
        return f(*args, **kwargs)
    return decorated

def validate_signup_data(data):
    errors = []
    required_fields = {
        'first_name': 'First name is required',
        'last_name': 'Last name is required',
        'birthday': 'Birthday is required (MM-DD format)',
        'nickname': 'Nickname is required',
        'department': 'Department is required',
        'level': 'Level is required',
        'whatsapp': 'WhatsApp number is required (11 digits)',
        'password': 'Password is required (min 10 characters)'
    }
    
    for field, message in required_fields.items():
        if not data.get(field):
            errors.append(message)

    if data.get('birthday') and not re.match(r'^\d{2}-\d{2}$', data['birthday']):
        errors.append('Birthday must be in MM-DD format')

    if data.get('whatsapp') and not re.match(r'^\d{11}$', data['whatsapp']):
        errors.append('WhatsApp number must be 11 digits')

    if data.get('password') and len(data['password']) < 10:
        errors.append('Password must be at least 10 characters')

    return errors

def user_exists(nickname, whatsapp):
    return users_collection.find_one({
        '$or': [
            {'nickname': nickname.lower()},
            {'whatsapp': whatsapp}
        ]
    })

def create_user(data):
    user = {
        'first_name': data['first_name'].strip(),
        'last_name': data['last_name'].strip(),
        'birthday': data['birthday'],
        'nickname': data['nickname'].strip().lower(),
        'department': data['department'].upper(),
        'level': data['level'].upper(),
        'whatsapp': data['whatsapp'],
        'email': data.get('email', '').strip().lower(),
        'password': generate_password_hash(data['password']),
        'created_at': get_wat_time(),
        'updated_at': get_wat_time(),
        'last_login': None,
        'status': 'active',
        'last_seen': None,
        'last_notification_check': datetime.min.replace(tzinfo=timezone.utc)
    }
    result = users_collection.insert_one(user)
    return result.inserted_id

def generate_token(user_id):
    payload = {
        'user_id': str(user_id),
        'exp': get_wat_time() + JWT_EXPIRATION
    }
    return jwt.encode(payload, JWT_SECRET, algorithm=JWT_ALGORITHM)

def authenticate_user(nickname, department, password):
    user = users_collection.find_one({
        'nickname': nickname.strip().lower(),
        'department': department.upper()
    })
    
    if user and check_password_hash(user['password'], password):
        users_collection.update_one(
            {'_id': user['_id']},
            {'$set': {
                'last_login': get_wat_time(),
                'status': 'online',
                'last_seen': get_wat_time()
            }}
        )
        return user
    return None

def sanitize_user_data(user):
    return {
        'id': str(user['_id']),
        'first_name': user['first_name'],
        'last_name': user['last_name'],
        'nickname': user['nickname'],
        'department': user['department'],
        'level': user['level'],
        'email': user.get('email', ''),
        'last_login': user.get('last_login'),
        'status': user.get('status', 'active'),
        'updated_at': user.get('updated_at')
    }

def validate_announcement_data(data):
    errors = []
    required_fields = {
        'title': 'Title is required',
        'content': 'Content is required',
        'badge': 'Badge type is required',
        'target': 'Target audience is required'
    }
    
    for field, message in required_fields.items():
        if not data.get(field):
            errors.append(message)
    
    valid_badges = ['notice', 'warning', 'new', 'important', 'event']
    if data.get('badge') and data['badge'] not in valid_badges:
        errors.append(f'Invalid badge type. Must be one of: {", ".join(valid_badges)}')
    
    valid_target_types = ['all', 'department', 'level', 'user']
    if data.get('target') and data['target'].get('type') not in valid_target_types:
        errors.append(f'Invalid target type. Must be one of: {", ".join(valid_target_types)}')
    
    return errors

def ensure_admin_exists():
    """Ensure the admin account exists in database"""
    admin_email = os.environ.get('ADMIN_EMAIL')
    admin_password = os.environ.get('ADMIN_PASSWORD')
    
    if not admin_email or not admin_password:
        raise ValueError("Admin credentials not configured in environment variables")
    
    admin = users_collection.find_one({'email': admin_email})
    
    if not admin:
        # Create the admin account if it doesn't exist
        admin_data = {
            'first_name': os.environ.get('ADMIN_FIRST_NAME', 'Admin'),
            'last_name': os.environ.get('ADMIN_LAST_NAME', 'User'),
            'email': admin_email,
            'password': generate_password_hash(admin_password),
            'role': 'admin',
            'created_at': get_wat_time(),
            'updated_at': get_wat_time(),
            'last_login': None,
            'status': 'active'
        }
        users_collection.insert_one(admin_data)
        print("✅ Admin account created")
    else:
        # Update password if it has changed in .env
        if not check_password_hash(admin['password'], admin_password):
            users_collection.update_one(
                {'email': admin_email},
                {'$set': {
                    'password': generate_password_hash(admin_password),
                    'updated_at': get_wat_time()
                }}
            )
            print("✅ Admin password updated")

def authenticate_admin(email, password):
    """Authenticate the predefined admin user"""
    admin_email = os.environ.get('ADMIN_EMAIL')
    admin_password = os.environ.get('ADMIN_PASSWORD')
    
    # Verify it's our predefined admin
    if email.strip().lower() != admin_email.lower():
        return None
    
    # Verify password matches .env
    if not check_password_hash(users_collection.find_one({'email': admin_email})['password'], admin_password):
        return None
    
    # Get or create admin record
    admin = users_collection.find_one({'email': admin_email})
    
    if not admin:
        ensure_admin_exists()
        admin = users_collection.find_one({'email': admin_email})
    
    # Update last login
    users_collection.update_one(
        {'_id': admin['_id']},
        {'$set': {
            'last_login': get_wat_time(),
            'status': 'online'
        }}
    )
    
    return admin

@app.route('/api/users/update', methods=['PUT'])
@requires_auth
def update_user_profile():
    try:
        data = request.get_json()
        user_id = request.user_id
        
        if not data:
            return jsonify({'success': False, 'error': 'No data provided'}), 400
            
        # Validate data
        validation_errors = {}
        
        if 'first_name' in data and not data['first_name'].strip():
            validation_errors['first_name'] = 'First name is required'
            
        if 'last_name' in data and not data['last_name'].strip():
            validation_errors['last_name'] = 'Last name is required'
            
        if 'email' in data and not re.match(r'^[^@]+@[^@]+\.[^@]+$', data['email']):
            validation_errors['email'] = 'Invalid email format'
            
        if 'whatsapp' in data and not re.match(r'^\d{11,13}$', data['whatsapp']):
            validation_errors['whatsapp'] = 'WhatsApp number must be 11-13 digits'
            
        if 'birthday' in data and not re.match(r'^\d{2}-\d{2}$', data['birthday']):
            validation_errors['birthday'] = 'Birthday must be in MM-DD format'
            
        if validation_errors:
            return jsonify({'success': False, 'error': 'Validation failed', 'errors': validation_errors}), 400
            
        # Prepare update data
        update_data = {
            'first_name': data.get('first_name'),
            'last_name': data.get('last_name'),
            'department': data.get('department'),
            'level': data.get('level'),
            'email': data.get('email'),
            'whatsapp': data.get('whatsapp'),
            'birthday': data.get('birthday'),
            'updated_at': get_wat_time()
        }
        
        # Remove None values
        update_data = {k: v for k, v in update_data.items() if v is not None}
        
        # Check if email is being changed to one that already exists
        if 'email' in update_data:
            existing_user = users_collection.find_one({
                'email': update_data['email'],
                '_id': {'$ne': ObjectId(user_id)}
            })
            if existing_user:
                return jsonify({'success': False, 'error': 'Email already in use'}), 400
        
        # Update in database
        result = users_collection.update_one(
            {'_id': ObjectId(user_id)},
            {'$set': update_data}
        )
        
        if result.modified_count == 0:
            return jsonify({'success': False, 'error': 'No changes made'}), 400
            
        # Get updated user
        user = users_collection.find_one({'_id': ObjectId(user_id)})
        return jsonify({
            'success': True,
            'user': sanitize_user_data(user)
        })
        
    except Exception as e:
        return jsonify({'success': False, 'error': str(e)}), 500

@app.route('/')
def home():
    return jsonify({"status": "NAITS Backend Running", "time_in_nigeria": get_wat_time().isoformat()})

@app.route('/api/auth/signup', methods=['POST'])
def signup():
    if request.method == 'OPTIONS':
        return _build_cors_preflight_response()
    
    try:
        data = request.get_json()
        if not data:
            return jsonify({'success': False, 'error': 'No data provided'}), 400

        errors = validate_signup_data(data)
        if errors:
            return jsonify({'success': False, 'error': 'Validation failed', 'details': errors}), 400

        if user_exists(data['nickname'], data['whatsapp']):
            return jsonify({'success': False, 'error': 'User already exists'}), 400

        user_id = create_user(data)
        user = users_collection.find_one({'_id': user_id})
        token = generate_token(user_id)
        
        return jsonify({
            'success': True,
            'token': token,
            'user': sanitize_user_data(user),
            'message': 'Registration successful'
        }), 201

    except Exception as e:
        return jsonify({'success': False, 'error': str(e)}), 500

@app.route('/api/auth/signin', methods=['POST'])
def signin():
    if request.method == 'OPTIONS':
        return _build_cors_preflight_response()
    
    try:
        data = request.get_json()
        if not data:
            return jsonify({'success': False, 'error': 'No data provided'}), 400

        if not all(k in data for k in ['nickname', 'department', 'password']):
            return jsonify({'success': False, 'error': 'Missing fields'}), 400
        
        data['nickname'] = data['nickname'].strip().lower()
        data['department'] = data['department'].upper()

        user = authenticate_user(data['nickname'], data['department'], data['password'])
        if not user:
            return jsonify({'success': False, 'error': 'Invalid credentials'}), 401

        token = generate_token(user['_id'])

        return jsonify({
            'success': True,
            'token': token,
            'user': sanitize_user_data(user),
            'message': 'Login successful'
        }), 200

    except Exception as e:
        return jsonify({'success': False, 'error': str(e)}), 500

@app.route('/api/auth/logout', methods=['POST'])
@requires_auth
def user_logout():
    try:
        users_collection.update_one(
            {'_id': ObjectId(request.user_id)},
            {'$set': {
                'status': 'offline',
                'last_seen': get_wat_time()
            }}
        )
        return jsonify({'success': True, 'message': 'Logged out successfully'})
    except Exception as e:
        return jsonify({'success': False, 'error': str(e)}), 500

@app.route('/api/auth/heartbeat', methods=['POST'])
@requires_auth
def user_heartbeat():
    """Endpoint for clients to send regular heartbeats"""
    try:
        users_collection.update_one(
            {'_id': ObjectId(request.user_id)},
            {
                '$set': {
                    'status': 'online',
                    'last_active': get_wat_time(),
                    'last_seen': get_wat_time()
                }
            }
        )
        return jsonify({'success': True})
    except Exception as e:
        return jsonify({'success': False, 'error': str(e)}), 500

def check_user_status():
    """Background task to update user statuses"""
    try:
        now = get_wat_time()
        
        # Mark idle users (online but inactive for IDLE_THRESHOLD minutes)
        idle_threshold = now - timedelta(minutes=STATUS_CONFIG['IDLE_THRESHOLD'])
        users_collection.update_many(
            {
                'status': 'online',
                'last_active': {'$lt': idle_threshold}
            },
            {'$set': {'status': 'idle'}}
        )
        
        # Mark offline users (inactive for OFFLINE_THRESHOLD minutes)
        offline_threshold = now - timedelta(minutes=STATUS_CONFIG['OFFLINE_THRESHOLD'])
        users_collection.update_many(
            {
                '$or': [
                    {'status': 'online'},
                    {'status': 'idle'}
                ],
                'last_active': {'$lt': offline_threshold}
            },
            {'$set': {'status': 'offline'}}
        )
    except Exception as e:
        print(f"Error in status check: {str(e)}")

@app.route('/api/users/status/<user_id>', methods=['GET'])
@requires_auth
def get_user_status(user_id):
    """Get real-time user status with verification"""
    try:
        user = users_collection.find_one(
            {'_id': ObjectId(user_id)},
            {'status': 1, 'last_active': 1, 'first_name': 1, 'department': 1}
        )
        
        if not user:
            return jsonify({'success': False, 'error': 'User not found'}), 404
        
        status = user.get('status', 'offline')
        last_active = user.get('last_active')
        
        # Real-time verification for online/idle status
        if status in ['online', 'idle']:
            inactive_for = (get_wat_time() - last_active).total_seconds() / 60
            
            if inactive_for > STATUS_CONFIG['OFFLINE_THRESHOLD']:
                status = 'offline'
                users_collection.update_one(
                    {'_id': ObjectId(user_id)},
                    {'$set': {'status': 'offline'}}
                )
            elif inactive_for > STATUS_CONFIG['IDLE_THRESHOLD']:
                status = 'idle'
                if user['status'] != 'idle':
                    users_collection.update_one(
                        {'_id': ObjectId(user_id)},
                        {'$set': {'status': 'idle'}}
                    )
        
        return jsonify({
            'success': True,
            'status': status,
            'last_seen': last_active.isoformat() if last_active else None,
            'first_name': user.get('first_name'),
            'department': user.get('department'),
        })
    except Exception as e:
        return jsonify({'success': False, 'error': str(e)}), 500

@app.route('/api/admin/auth/signin', methods=['POST', 'OPTIONS'])
def admin_signin():
    if request.method == 'OPTIONS':
        return _build_cors_preflight_response()
    
    try:
        data = request.get_json()
        if not data:
            return jsonify({'success': False, 'error': 'No data provided'}), 400

        if not all(k in data for k in ['email', 'password']):
            return jsonify({'success': False, 'error': 'Missing email or password'}), 400
        
        email = data['email'].strip().lower()
        password = data['password']

        admin = authenticate_admin(email, password)
        if not admin:
            return jsonify({'success': False, 'error': 'Invalid admin credentials'}), 401

        token = generate_token(admin['_id'])

        return jsonify({
            'success': True,
            'token': token,
            'admin': {
                'id': str(admin['_id']),
                'first_name': admin.get('first_name', 'Admin'),
                'last_name': admin.get('last_name', 'User'),
                'email': admin['email'],
                'role': 'admin'
            },
            'message': 'Admin login successful'
        }), 200

    except Exception as e:
        return jsonify({'success': False, 'error': str(e)}), 500

@app.route('/api/users/change-password', methods=['POST'])
@requires_auth
def change_password():
    try:
        data = request.get_json()
        user_id = request.user_id
        
        if not data or not all(k in data for k in ['current_password', 'new_password']):
            return jsonify({'success': False, 'error': 'Missing required fields'}), 400
            
        user = users_collection.find_one({'_id': ObjectId(user_id)})
        if not user:
            return jsonify({'success': False, 'error': 'User not found'}), 404
            
        # Verify current password
        if not check_password_hash(user['password'], data['current_password']):
            return jsonify({'success': False, 'error': 'Current password is incorrect'}), 401
            
        # Update password
        users_collection.update_one(
            {'_id': ObjectId(user_id)},
            {'$set': {
                'password': generate_password_hash(data['new_password']),
                'updated_at': get_wat_time()
            }}
        )
        
        return jsonify({'success': True, 'message': 'Password updated successfully'})
        
    except Exception as e:
        return jsonify({'success': False, 'error': str(e)}), 500

if __name__ == '__main__':
    app.run(
        host=os.environ.get('HOST', '0.0.0.0'),
        port=int(os.environ.get('PORT', 5000)),
        debug=os.environ.get('FLASK_ENV') == 'development'
    )