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

app = Flask(__name__)
app.secret_key = 'your_secret_key'  # Change this to a secure random key
app.config['PERMANENT_SESSION_LIFETIME'] = timedelta(minutes=10)
#
# MongoDB setup
client = MongoClient('mongodb://localhost:27017/')
db = client['rbac_db']

def get_db():
    return db

def init_db():
    if 'users' not in db.list_collection_names():
        db.create_collection('users')
    if 'roles' not in db.list_collection_names():
        db.create_collection('roles')
    if 'api_endpoints' not in db.list_collection_names():
        db.create_collection('api_endpoints')

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
def login_required(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if 'user_id' not in session:
            return redirect(url_for('login'))
        return f(*args, **kwargs)
    return decorated_function

def role_required(role):
    def decorator(f):
        @wraps(f)
        def decorated_function(*args, **kwargs):
            if 'role' not in session or session['role'] != role:
                flash('You do not have permission to access this page.', 'error')
                return redirect(url_for('index'))
            return f(*args, **kwargs)
        return decorated_function
    return decorator

# Routes
@app.route('/')
def index():
    return render_template('index.html')

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
    
    # Connect to MongoDB
    # users_collection = db['users']

    # Find the user in MongoDB
    user = db.users.find_one({'username': username})
    
    if user:
        totp_secret = user['totp_secret']
        totp_uri = pyotp.totp.TOTP(totp_secret).provisioning_uri(name=username, issuer_name="ZTI_KARE")
       
        qr = qrcode.QRCode(version=1, box_size=10, border=5)
        qr.add_data(totp_uri)
        qr.make(fit=True)
        img = qr.make_image(fill_color="black", back_color="white")
       
        # Round the corners and resize as before
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
       
        # Close the MongoDB connection
        # client.close()

        return jsonify({'qr_code': img_str})
    else:
        # Close the MongoDB connection
        # client.close()
        return jsonify({'error': 'User not found'}), 404

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
                session['user_id'] = str(user['_id'])
                session['username'] = user['username']
                session['role'] = user['role']
                session.permanent = True
                session['last_activity'] = datetime.now(timezone.utc).isoformat()
                return redirect(url_for('dashboard'))
            else:
                flash('Invalid TOTP code', 'error')
        else:
            flash('Invalid username or password', 'error')
    return render_template('login.html')

@app.route('/update_activity', methods=['POST'])
@login_required
def update_activity():
    session['last_activity'] = datetime.now(timezone.utc).isoformat()
    return '', 204 

@app.route('/check_session', methods=['GET'])
def check_session():
    if 'user_id' in session and 'last_activity' in session:
        last_activity = datetime.fromisoformat(session['last_activity'])
        if datetime.now(timezone.utc) - last_activity > timedelta(minutes=2):
            session.clear()
            return jsonify({'valid': False})
    return jsonify({'valid': 'user_id' in session})

@app.route('/logout')
def logout():
    session.clear()
    return redirect(url_for('login'))

@app.route('/dashboard', methods=['GET', 'POST'])
@login_required
def dashboard():
    user_role = session.get('role')

    if user_role == 'admin' and request.method == 'POST':
        action = request.form.get('action')
        
        if action == 'create_endpoint':
            name = request.form.get('name')
            endpoint = request.form.get('endpoint')
            method = request.form.get('method')
            description = request.form.get('description')
            
            try:
                db.api_endpoints.insert_one({
                    'name': name,
                    'endpoint': endpoint,
                    'method': method,
                    'description': description
                })
                flash('API endpoint created successfully', 'success')
            except Exception as e:
                flash(f'Error creating API endpoint: {str(e)}', 'error')
        
        elif action == 'delete_endpoint':
            endpoint_id = request.form.get('endpoint_id')
            db.api_endpoints.delete_one({'_id': ObjectId(endpoint_id)})
            flash('API endpoint deleted successfully', 'success')
        
        elif action == 'change_role':
            user_id = request.form.get('user_id')
            new_role = request.form.get('new_role')
            db.users.update_one({'_id': ObjectId(user_id)}, {'$set': {'role': new_role}})
            flash('User role updated successfully', 'success')

    if user_role == 'admin':
        users = list(db.users.find({}, {'_id': 1, 'username': 1, 'role': 1}))
        roles = list(db.roles.find({}, {'name': 1}))
        api_endpoints = list(db.api_endpoints.find())
    else:
        users = roles = api_endpoints = None

    return render_template('dashboard.html', user_role=user_role, users=users, roles=roles, api_endpoints=api_endpoints)

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

        if action == 'change_role':
            username = data.get('username')
            new_role = data.get('new_role')
            user = db.users.find_one({'username': username})
            if user:
                db.users.update_one({'_id': user['_id']}, {'$set': {'role': new_role}})
                return jsonify({'status': 'success', 'message': 'User role updated successfully'})
            else:
                return jsonify({'status': 'error', 'message': 'User not found'})

        elif action == 'change_password':
            username = data.get('username')
            new_password = data.get('new_password')
            user = db.users.find_one({'username': username})
            if user:
                hashed_password = generate_password_hash(new_password)
                db.users.update_one({'_id': user['_id']}, {'$set': {'password': hashed_password}})
                return jsonify({'status': 'success', 'message': 'User password updated successfully'})
            else:
                return jsonify({'status': 'error', 'message': 'User not found'})

        # Keep the existing actions
        elif action == 'create_user':
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
            # Purge duplicate roles
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

    # For GET requests, return the list of users and roles
    users = list(db.users.find({}, {'password': 0, 'totp_secret': 0}))
    for user in users:
        user['_id'] = str(user['_id'])  # Convert ObjectId to string
    roles = list(db.roles.find({}, {'_id': 0, 'name': 1}))
    return jsonify({'users': users, 'roles': roles})


@app.route('/admin/change_role', methods=['POST'])
@login_required
@role_required('admin')
def change_role():
    user_id = request.form['user_id']
    new_role = request.form['new_role']
    admin_password = request.form['admin_password']

    admin = db.users.find_one({'_id': ObjectId(session['user_id'])})

    if check_password_hash(admin['password'], admin_password):
        db.users.update_one({'_id': ObjectId(user_id)}, {'$set': {'role': new_role}})
        flash('User role updated successfully', 'success')
    else:
        flash('Invalid admin password', 'error')

    return redirect(url_for('admin'))

@app.route('/admin/create_role', methods=['POST'])
@login_required
@role_required('admin')
def create_role():
    new_role = request.form['new_role']
    admin_password = request.form['admin_password']

    admin = db.users.find_one({'_id': ObjectId(session['user_id'])})

    if check_password_hash(admin['password'], admin_password):
        db.roles.insert_one({'name': new_role})
        flash('New role created successfully', 'success')
    else:
        flash('Invalid admin password', 'error')

    return redirect(url_for('admin'))

if __name__ == '__main__':
    app.run(debug=True,port=5000)