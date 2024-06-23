from flask import Flask, render_template, request, redirect, url_for, session, flash, make_response, jsonify
from functools import wraps
from pymongo import MongoClient
from bson.objectid import ObjectId
from werkzeug.security import generate_password_hash, check_password_hash
import pyotp
import qrcode
import io
import base64
from datetime import datetime, timedelta, timezone
from PIL import Image, ImageDraw
import psutil
from flask import jsonify
from collections import deque
import time
import re
from flask import session, request, redirect, url_for
from flask_jwt_extended import verify_jwt_in_request, exceptions
from flask_jwt_extended import JWTManager, create_access_token, create_refresh_token, jwt_required, get_jwt_identity

import logging
from logging.handlers import RotatingFileHandler
import os

def setup_logging(app):
    if not os.path.exists('logs'):
        os.mkdir('logs')
    file_handler = RotatingFileHandler('logs/app.log', maxBytes=10240, backupCount=100)
    file_handler.setFormatter(logging.Formatter(
        '%(asctime)s %(levelname)s: %(message)s [in %(pathname)s:%(lineno)d]'
    ))
    file_handler.setLevel(logging.INFO)
    app.logger.addHandler(file_handler)
    app.logger.setLevel(logging.INFO)
    app.logger.info('Application startup')



max_length = 3
timestamps = deque(maxlen=max_length)
network_usage = deque(maxlen=max_length)

last_update_time = 0
app = Flask(__name__,static_folder="static")
app.secret_key = '9nvFXEse8c9foNRA4V9Y4djCyv4snMvY'  # Change this to a secure random key
app.config['PERMANENT_SESSION_LIFETIME'] = timedelta(minutes=2)
app.config['JWT_SECRET_KEY'] = 'hTAKhXQBVBs7aSuT4Xn1cGzmvj4mJmpp'  # Change this!
app.config['JWT_ACCESS_TOKEN_EXPIRES'] = timedelta(minutes=2)
app.config['JWT_REFRESH_TOKEN_EXPIRES'] = timedelta(days=30)
app.config['JWT_TOKEN_LOCATION'] = ['cookies']
app.config["JWT_COOKIE_SECURE"] = False
jwt = JWTManager(app)
# MongoDB setup
client = MongoClient('mongodb://localhost:27017/')
db = client['rbac_db']
setup_logging(app)
def get_db():
    return db

def init_db():
    if 'users' not in db.list_collection_names():
        db.create_collection('users')
    if 'roles' not in db.list_collection_names():
        db.create_collection('roles')
    if 'api_endpoints' not in db.list_collection_names():
        db.create_collection('api_endpoints')
    if 'admin_action_passwords' not in db.list_collection_names():
        db.create_collection('admin_action_passwords')
        db.admin_action_passwords.create_index('user_id', unique=True)
    # Add default roles if they don't exist
    if db.roles.count_documents({'name': 'admin'}) == 0:
        db.roles.insert_one({'name': 'admin'})
    if db.roles.count_documents({'name': 'user'}) == 0:
        db.roles.insert_one({'name': 'user'})

    # Create indexes
    db.users.create_index('username', unique=True)
    db.api_endpoints.create_index('name', unique=True)
    db.api_endpoints.create_index('endpoint', unique=True)

# Call init_db() at the start of your application
init_db()

# Helper functions
# def login_required(f):
#     @wraps(f)
#     def decorated_function(*args, **kwargs):
#         if 'user_id' not in session:
#             return redirect(url_for('login'))
#         return f(*args, **kwargs)
#     return decorated_function

def log_action(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        user_id = get_jwt_identity()
        app.logger.info(f'User {user_id} performed action: {f.__name__}')
        return f(*args, **kwargs)
    return decorated_function

def log_specific_action(action, details=None):
    user_id = get_jwt_identity()
    ip_address = request.remote_addr
    user_agent = request.user_agent.string
    log_entry = f'User {user_id} from IP {ip_address} using {user_agent} performed action: {action}'
    if details:
        log_entry += f' | Details: {details}'
    app.logger.info(log_entry)

def db_operation_logger(operation):
    def decorator(f):
        @wraps(f)
        def wrapped(*args, **kwargs):
            result = f(*args, **kwargs)
            user_id = get_jwt_identity()
            app.logger.info(f'User {user_id} performed DB operation: {operation} | Args: {args} | Kwargs: {kwargs}')
            return result
        return wrapped
    return decorator

def sensitive_operation_logger(operation):
    def decorator(f):
        @wraps(f)
        def wrapped(*args, **kwargs):
            user_id = get_jwt_identity()
            app.logger.info(f'User {user_id} attempting sensitive operation: {operation}')
            result = f(*args, **kwargs)
            app.logger.info(f'User {user_id} completed sensitive operation: {operation}')
            return result
        return wrapped
    return decorator

@app.errorhandler(Exception)
def handle_exception(e):
    app.logger.error(f'Unhandled exception: {str(e)}', exc_info=True)

def login_required(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if request.is_json:
            try:
                verify_jwt_in_request()
            except exceptions.JWTExtendedException:
                return jsonify({"msg": "Missing or invalid token"}), 401
        elif 'user_id' not in session:
            return redirect(url_for('login'))
        return f(*args, **kwargs)
    return decorated_function

def role_required(role):
    def decorator(f):
        @wraps(f)
        @login_required
        def decorated_function(*args, **kwargs):
            if request.is_json:
                current_user_id = get_jwt_identity()
                user = db.users.find_one({'_id': ObjectId(current_user_id)})
            else:
                user = db.users.find_one({'_id': ObjectId(session['user_id'])})
            
            if user['role'] != role:
                if request.is_json:
                    return jsonify({"msg": "Insufficient permissions"}), 403
                else:
                    return redirect(url_for('error403'))
            return f(*args, **kwargs)
        return decorated_function
    return decorator


# Routes
@app.route('/')
def index():
    return render_template('index.html')

@app.route('/403')
def error403():
    return render_template('403.html')

@app.route('/404')
def error404():
    return render_template('404.html')

@app.route('/401')
def error401():
    return render_template('401.html')

@app.errorhandler(404)
def page_not_found(e):
    return redirect(url_for('error404'))

@app.errorhandler(401)
def page_not_found(e):
    return redirect(url_for('error401'))

@app.route('/register', methods=['GET', 'POST'])
def register():
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']
        confirm_password = request.form['confirm_password']
        totp_code = request.form['totp_code']
        totp_secret = request.form['totp_secret']
        role = 'user'  # Default role for new users

        user = db.users.find_one({'username': username})

        if user:
            flash('Username already exists', 'error')
        elif password != confirm_password:
            flash('Passwords do not match', 'error')
        else:
            totp = pyotp.TOTP(totp_secret)
            if totp.verify(totp_code):
                hashed_password = generate_password_hash(password)
                db.users.insert_one({
                    'username': username,
                    'password': hashed_password,
                    'role': role,
                    'totp_secret': totp_secret
                })
                flash('Registration successful. Please log in.', 'success')
                return redirect(url_for('login'))
            else:
                flash('Invalid TOTP code', 'error')

    return render_template('register.html')

@app.route('/generate_qr', methods=['POST'])
def generate_qr():
    username = request.form['username']
    totp_secret = pyotp.random_base32()
    totp_uri = pyotp.totp.TOTP(totp_secret).provisioning_uri(name=username, issuer_name="ZTI_KARE")
    
    qr = qrcode.QRCode(version=1, box_size=10, border=5)
    qr.add_data(totp_uri)
    qr.make(fit=True)
    img = qr.make_image(fill_color="black", back_color="white")
    
    img = img.convert("RGBA")
    width, height = img.size
    mask = Image.new('L', (width, height), 0)
    draw = ImageDraw.Draw(mask)
    draw.rounded_rectangle((0, 0, width, height), radius=20, fill=255)
    img.putalpha(mask)
    
    img = img.resize((200, 200))
    
    buffered = io.BytesIO()
    img.save(buffered, format="PNG")
    img_str = base64.b64encode(buffered.getvalue()).decode()

    return jsonify({'qr_code': img_str, 'totp_secret': totp_secret})

@app.route('/generate_qr_for_user', methods=['POST'])
@login_required
@role_required('admin')
def generate_qr_for_user():
    username = request.form['username']
    user = db.users.find_one({'username': username})
    
    if user:
        totp_secret = user['totp_secret']
        totp_uri = pyotp.totp.TOTP(totp_secret).provisioning_uri(name=username, issuer_name="ZTI_KARE")
       
        qr = qrcode.QRCode(version=1, box_size=10, border=5)
        qr.add_data(totp_uri)
        qr.make(fit=True)
        img = qr.make_image(fill_color="black", back_color="white")
       
        img = img.convert("RGBA")
        width, height = img.size
        mask = Image.new('L', (width, height), 0)
        draw = ImageDraw.Draw(mask)
        draw.rounded_rectangle((0, 0, width, height), radius=20, fill=255)
        img.putalpha(mask)
        img = img.resize((200, 200))
       
        buffered = io.BytesIO()
        img.save(buffered, format="PNG")
        img_str = base64.b64encode(buffered.getvalue()).decode()

        return jsonify({'qr_code': img_str})
    else:
        return jsonify({'error': 'User not found'}), 404

# @app.route('/login', methods=['GET', 'POST'])
# def login():
    # if request.method == 'POST':
    #     username = request.form['username']
    #     password = request.form['password']
    #     totp_code = request.form['totp_code']
    #     user = db.users.find_one({'username': username})
    #     if user and check_password_hash(user['password'], password):
    #         totp = pyotp.TOTP(user['totp_secret'])
    #         if totp.verify(totp_code):
    #             session['user_id'] = str(user['_id'])
    #             session['username'] = user['username']
    #             session['role'] = user['role']
    #             session.permanent = True
    #             session['last_activity'] = datetime.now(timezone.utc).isoformat()
    #             return redirect(url_for('dashboard'))
    #         else:
    #             flash('Invalid TOTP code', 'error')
    #     else:
    #         flash('Invalid username or password', 'error')
    # return render_template('login.html')
# @app.route('/login', methods=['GET', 'POST'])
# def login():
#     if request.method == 'GET':
#         return render_template('login.html')
    
#     username = request.form.get('username') or request.json.get('username')
#     password = request.form.get('password') or request.json.get('password')
#     totp_code = request.form.get('totp_code') or request.json.get('totp_code')
    
#     user = db.users.find_one({'username': username})
#     if user and check_password_hash(user['password'], password):
#         totp = pyotp.TOTP(user['totp_secret'])
#         if totp.verify(totp_code):
#             if request.is_json:
#                 access_token = create_access_token(identity=str(user['_id']))
#                 refresh_token = create_refresh_token(identity=str(user['_id']))
#                 return jsonify(access_token=access_token, refresh_token=refresh_token), 200
#             else:
#                 session['user_id'] = str(user['_id'])
#                 session['username'] = user['username']
#                 session['role'] = user['role']
#                 session.permanent = True
#                 session['last_activity'] = datetime.now(timezone.utc).isoformat()
#                 return redirect(url_for('dashboard'))
#         else:
#             flash('Invalid TOTP code', 'error')
#     else:
#         flash('Invalid username or password', 'error')
    
#     if request.is_json:
#         return jsonify({"msg": "Bad username, password, or TOTP code"}), 401
#     return render_template('login.html')


# @app.route('/login', methods=['GET', 'POST'])
# def login():
#     if request.method == 'POST':
#         username = request.form['username']
#         password = request.form['password']
#         totp_code = request.form['totp_code']
#         user = db.users.find_one({'username': username})
#         if user and check_password_hash(user['password'], password):
#             totp = pyotp.TOTP(user['totp_secret'])
#             if totp.verify(totp_code):
#                 access_token = create_access_token(identity=str(user['_id']))
#                 refresh_token = create_refresh_token(identity=str(user['_id']))
#                 return jsonify(access_token=access_token, refresh_token=refresh_token), 200
#             else:
#                 return jsonify({"msg": "Invalid TOTP code"}), 401
#         else:
#             return jsonify({"msg": "Bad username or password"}), 401
#     return render_template('login.html')

@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']
        totp_code = request.form['totp_code']
        
        user = db.users.find_one({'username': username})
        if user and check_password_hash(user['password'], password):
            totp = pyotp.TOTP(user['totp_secret'])
            if totp.verify(totp_code):
                access_token = create_access_token(identity=str(user['_id']))
                refresh_token = create_refresh_token(identity=str(user['_id']))
                
                resp = make_response(redirect(url_for('dashboard')))
                resp.set_cookie('access_token_cookie', access_token, samesite='Lax')
                resp.set_cookie('refresh_token_cookie', refresh_token, samesite='Lax' )
                
                flash('Login successful', 'success')
                return resp
            else:
                flash('Invalid TOTP code', 'error')
        else:
            flash('Invalid username or password', 'error')
    
    return render_template('login.html')

@app.route('/api/login', methods=['POST'])
def api_login():
    data = request.get_json()
    username = data.get('username')
    password = data.get('password')
    totp_code = data.get('totp_code')

    user = db.users.find_one({'username': username})
    if not user or not check_password_hash(user['password'], password):
        return jsonify({"msg": "Invalid username or password"}), 401
    print("got till here")
    totp = pyotp.TOTP(user['totp_secret'])
    if not totp.verify(totp_code):
        return jsonify({"msg": "Invalid TOTP code"}), 401
    print("got till here2")
    access_token = create_access_token(identity=str(user['_id']))
    refresh_token = create_refresh_token(identity=str(user['_id']))
    print("got till here3")
    resp = jsonify({"msg": "Login successful"})
    resp.set_cookie('access_token_cookie', access_token, samesite='Lax')
    resp.set_cookie('refresh_token_cookie', refresh_token, samesite='Lax')
    return resp, 200

@app.route('/api/dashboard', methods=['GET'])
@jwt_required()
def api_dashboard():
    current_user_id = get_jwt_identity()
    user = db.users.find_one({'_id': ObjectId(current_user_id)})
    return jsonify({"role": user['role'], "username": user['username']})

@app.route('/refresh', methods=['POST'])
@jwt_required(refresh=True)
def refresh():
    current_user = get_jwt_identity()
    access_token = create_access_token(identity=current_user)
    return jsonify(access_token=access_token), 200

@app.route('/update_activity', methods=['POST'])
@jwt_required()
def update_activity():
    current_user_id = get_jwt_identity()
    session['last_activity'] = datetime.now(timezone.utc).isoformat()
    return '', 204 

# @app.route('/check_session', methods=['GET'])
# def check_session():
#     if 'user_id' in session and 'last_activity' in session:
#         last_activity = datetime.fromisoformat(session['last_activity'])
#         if datetime.now(timezone.utc) - last_activity > timedelta(minutes=2):
#             session.clear()
#             return jsonify({'valid': False})
#     return jsonify({'valid': 'user_id' in session})

@app.route('/check_session', methods=['GET'])
@jwt_required()
def check_session():
    return jsonify({'valid': True})

# @app.route('/logout')
# def logout():
#     session.clear()
#     return redirect(url_for('login'))

@app.route('/logout', methods=['GET', 'POST'])
@login_required
def logout():
    if request.method == 'GET' or not request.is_json:
        session.clear()
        return redirect(url_for('index'))
    else:
        # For API requests, you might want to implement a token blacklist here
        return jsonify({"msg": "Successfully logged out"}), 200

# @app.route('/dashboard')
# @login_required
# def dashboard():
#     user_role = session.get('role')
#     return render_template('dashboard.html', user_role=user_role)

@app.route('/dashboard')
@jwt_required()
def dashboard():
    current_user_id = get_jwt_identity()
    refresh_token = request.cookies.get("refresh_token_cookie")
    access_token = request.cookies.get("access_token_cookie")
    user = db.users.find_one({'_id': ObjectId(current_user_id)})
    
    if not user:
        return jsonify({"msg": "User not found"}), 404

    if request.is_json:
        # If it's an API request, return JSON
        return jsonify({
            "username": user['username'],
            "role": user['role'],
            "msg": "Dashboard data retrieved successfully"
        })
    else:
        # If it's a web request, render the dashboard template
        return render_template('dashboard.html', username=user['username'], role=user['role'],access_token=access_token,refresh_token=refresh_token)

@app.route('/admin/system_stats')
# @login_required
@jwt_required()
def system_stats():
    current_user_id = get_jwt_identity()
    global last_update_time
    current_time = time.time()
    
    # Only update stats every 10 seconds
    if current_time - last_update_time >= 10:
        last_update_time = current_time
        
        timestamps.append(current_time)
        
        # CPU Usage
        cpu = psutil.cpu_percent()
        cpu_usage = {
            "Used": cpu,
            "Free": 100 - cpu
        }
        
        # Memory Usage
        memory = psutil.virtual_memory()
        memory_usage = {
            "Used": memory.percent,
            "Free": 100 - memory.percent
        }
        
        # Disk Usage
        disk = psutil.disk_usage("/")
        disk_usage = {
            "Used": disk.percent,
            "Free": 100 - disk.percent
        }
        
        # Network Usage (in MB/s)
        network = sum(psutil.net_io_counters()._asdict().values()) / (1024 * 1024)
        network_usage.append(network)

    return jsonify({
        'timestamps': list(timestamps),
        'cpu_usage': cpu_usage,
        'memory_usage': memory_usage,
        'disk_usage': disk_usage,
        'network_usage': list(network_usage)
    })

@app.route('/admin', methods=['GET', 'POST'])
@login_required
@role_required('admin')
def admin():
    if request.method == 'POST':
        data = request.get_json()
        action = data.get('action')
        admin_password = data.get('admin_password')

        # Verify admin password
        admin_user = db.users.find_one({'_id': ObjectId(session['user_id'])})
        if not check_password_hash(admin_user['password'], admin_password):
            return jsonify({'status': 'error', 'message': 'Invalid admin password.'})

        if action == 'create_user':
            username = data.get('username')
            password = data.get('password')
            role = data.get('role')

            existing_user = db.users.find_one({'username': username})
            if existing_user:
                return jsonify({'status': 'error', 'message': 'Username already exists. Please choose a different username.'})
            
            totp_secret = pyotp.random_base32()
            hashed_password = generate_password_hash(password)
            try:
                db.users.insert_one({
                    'username': username,
                    'password': hashed_password,
                    'role': role,
                    'totp_secret': totp_secret
                })
                return jsonify({'status': 'success', 'message': 'New user created successfully'})
            except Exception as e:
                return jsonify({'status': 'error', 'message': f'An error occurred while creating the user: {str(e)}'})

        elif action == 'purge_roles':
            roles = db.roles.find()
            unique_roles = set()
            for role in roles:
                if role['name'] in unique_roles:
                    db.roles.delete_one({'_id': role['_id']})
                else:
                    unique_roles.add(role['name'])
            return jsonify({'status': 'success', 'message': 'Duplicate roles purged successfully'})

        elif action == 'create_role':
            new_role = data.get('new_role')
            existing_role = db.roles.find_one({'name': new_role})
            if existing_role:
                return jsonify({'status': 'error', 'message': 'Role already exists.'})

            try:
                db.roles.insert_one({'name': new_role})
                return jsonify({'status': 'success', 'message': 'New role created successfully'})
            except Exception as e:
                return jsonify({'status': 'error', 'message': f'An error occurred: {str(e)}'})

    # For GET requests, render the admin template
    return render_template('admin.html')

@app.route('/admin/manage_role', methods=['POST'])
@login_required
@role_required('admin')
def manage_role():
    data = request.get_json()
    username = data.get('username')
    new_role = data.get('new_role')
    admin_password = data.get('admin_password')

    # Verify admin password
    admin_user = db.users.find_one({'_id': ObjectId(session['user_id'])})
    if not check_password_hash(admin_user['password'], admin_password):
        return jsonify({'status': 'error', 'message': 'Invalid admin password.'})

    user = db.users.find_one({'username': username})
    if user:
        db.users.update_one({'_id': user['_id']}, {'$set': {'role': new_role}})
        return jsonify({'status': 'success', 'message': 'User role updated successfully'})
    else:
        return jsonify({'status': 'error', 'message': 'User not found'})

@app.route('/admin/delete_role', methods=['POST'])
@login_required
@role_required('admin')
def delete_role():
    data = request.get_json()
    role_name = data.get('role_name')
    admin_password = data.get('admin_password')

    # Verify admin password
    admin_user = db.users.find_one({'_id': ObjectId(session['user_id'])})
    if not check_password_hash(admin_user['password'], admin_password):
        return jsonify({'status': 'error', 'message': 'Invalid admin password.'})

    # Check if the role exists
    role = db.roles.find_one({'name': role_name})
    if not role:
        return jsonify({'status': 'error', 'message': 'Role not found.'})

    # Check if any users are using this role
    users_with_role = db.users.find_one({'role': role_name})
    if users_with_role:
        return jsonify({'status': 'error', 'message': 'Cannot delete role. Users are still assigned to this role.'})

    # Delete the role
    try:
        db.roles.delete_one({'name': role_name})
        return jsonify({'status': 'success', 'message': f'Role "{role_name}" deleted successfully'})
    except Exception as e:
        return jsonify({'status': 'error', 'message': f'An error occurred while deleting the role: {str(e)}'})

@app.route('/admin/manage_password', methods=['POST'])
@login_required
@role_required('admin')
def manage_password():
    data = request.get_json()
    username = data.get('username')
    new_password = data.get('new_password')
    admin_password = data.get('admin_password')

    # Verify admin password
    admin_user = db.users.find_one({'_id': ObjectId(session['user_id'])})
    if not check_password_hash(admin_user['password'], admin_password):
        return jsonify({'status': 'error', 'message': 'Invalid admin password.'})

    user = db.users.find_one({'username': username})
    if user:
        hashed_password = generate_password_hash(new_password)
        db.users.update_one({'_id': user['_id']}, {'$set': {'password': hashed_password}})
        return jsonify({'status': 'success', 'message': 'User password updated successfully'})
    else:
        return jsonify({'status': 'error', 'message': 'User not found'})

@app.route('/admin/users', methods=['GET'])
@login_required
@role_required('admin')
def get_users():
    users = list(db.users.find({}, {'password': 0, 'totp_secret': 0}))
    for user in users:
        user['_id'] = str(user['_id'])  # Convert ObjectId to string
    return jsonify({'users': users})

@app.route('/admin/roles', methods=['GET'])
@login_required
@role_required('admin')
def get_roles():
    roles = list(db.roles.find({}, {'_id': 0, 'name': 1}))
    return jsonify({'roles': roles})


@app.route('/admin/check_operation_passwords', methods=['GET'])
@login_required
@role_required('admin')
def check_operation_passwords():
    admin_id = ObjectId(session['user_id'])
    action_passwords = db.admin_action_passwords.find_one({'admin_id': admin_id})
    
    if not action_passwords:
        return jsonify({'all_set': False, 'passwords': {}})
    
    operations = ['create_role', 'manage_role', 'create_user', 'manage_users']
    all_set = all(action_passwords.get(op) for op in operations)
    return jsonify({
        'all_set': all_set, 
        'passwords': {op: bool(action_passwords.get(op)) for op in operations}
    })

@app.route('/admin/set_operation_passwords', methods=['POST'])
@login_required
@role_required('admin')
def set_operation_passwords():
    data = request.get_json()
    admin_id = ObjectId(session['user_id'])
    admin_user = db.users.find_one({'_id': admin_id})
    
    # Check if passwords are unique
    if len(set(data.values())) != len(data):
        return jsonify({'status': 'error', 'message': 'All operation passwords must be unique'})
    
    # Check if passwords meet requirements
    password_regex = re.compile(r'^(?=.*[a-z])(?=.*[A-Z])(?=.*\d)(?=.*[@$!%*?&])[A-Za-z\d@$!%*?&]{12,}$')
    for operation, password in data.items():
        if not password_regex.match(password):
            return jsonify({'status': 'error', 'message': f'{operation} password does not meet requirements'})
        
        # Check if password is different from admin password
        if check_password_hash(admin_user['password'], password):
            return jsonify({'status': 'error', 'message': f'{operation} password must be different from admin password'})
    
    action_passwords = {op: generate_password_hash(password) for op, password in data.items()}
    action_passwords['admin_id'] = admin_id

    db.admin_action_passwords.update_one(
        {'admin_id': admin_id},
        {'$set': action_passwords},
        upsert=True
    )
    
    return jsonify({'status': 'success', 'message': 'Operation passwords set successfully'})

@app.route('/admin/verify_operation_password', methods=['POST'])
@login_required
@role_required('admin')
def verify_operation_password():
    data = request.get_json()
    operation = data.get('operation')
    password = data.get('password')
    
    admin_id = ObjectId(session['user_id'])
    action_passwords = db.admin_action_passwords.find_one({'admin_id': admin_id})
    
    if not action_passwords or not action_passwords.get(operation):
        return jsonify({'status': 'error', 'message': 'Operation password not set'})
    
    if check_password_hash(action_passwords[operation], password):
        return jsonify({'status': 'success', 'message': 'Password verified'})
    else:
        return jsonify({'status': 'error', 'message': 'Incorrect password'})

@jwt.expired_token_loader
def expired_token_callback(jwt_header, jwt_payload):
    return jsonify({"msg": "Token has expired"}), 401

@jwt.invalid_token_loader
def invalid_token_callback(error):
    return jsonify({"msg": "Invalid token"}), 401

@app.route('/admin/reset_operation_password', methods=['POST'])
@login_required
@role_required('admin')
def reset_operation_password():
    data = request.get_json()
    operation = data.get('operation')
    current_password = data.get('current_password')
    new_password = data.get('new_password')
    
    admin_id = ObjectId(session['user_id'])
    admin_user = db.users.find_one({'_id': admin_id})
    action_passwords = db.admin_action_passwords.find_one({'admin_id': admin_id})
    
    if not action_passwords or not action_passwords.get(operation):
        return jsonify({'status': 'error', 'message': 'Operation password not set'})
    
    if not check_password_hash(action_passwords[operation], current_password):
        return jsonify({'status': 'error', 'message': 'Incorrect current password'})
    
    # Check if new password meets requirements
    password_regex = re.compile(r'^(?=.*[a-z])(?=.*[A-Z])(?=.*\d)(?=.*[@$!%*?&])[A-Za-z\d@$!%*?&]{12,}$')
    if not password_regex.match(new_password):
        return jsonify({'status': 'error', 'message': 'New password does not meet requirements'})
    
    # Check if new password is different from admin password
    if check_password_hash(admin_user['password'], new_password):
        return jsonify({'status': 'error', 'message': 'New password must be different from admin password'})
    
    # Check if new password is different from other operation passwords
    for op, pwd_hash in action_passwords.items():
        if op != 'admin_id' and op != operation and check_password_hash(pwd_hash, new_password):
            return jsonify({'status': 'error', 'message': 'New password must be different from other operation passwords'})
    
    # Update the password
    db.admin_action_passwords.update_one(
        {'admin_id': admin_id},
        {'$set': {operation: generate_password_hash(new_password)}}
    )
    
    return jsonify({'status': 'success', 'message': 'Operation password reset successfully'})


if __name__ == '__main__':
    app.run(debug=True)