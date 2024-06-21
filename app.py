from flask import Flask, render_template, request, redirect, url_for, session, flash, make_response, jsonify
from functools import wraps
import sqlite3
from werkzeug.security import generate_password_hash, check_password_hash
import pyotp
import qrcode
import io
import base64
from datetime import datetime, timedelta,timezone
from PIL import Image, ImageDraw
app = Flask(__name__)
app.secret_key = 'your_secret_key'  # Change this to a secure random key
app.config['PERMANENT_SESSION_LIFETIME'] = timedelta(minutes=2)
# Database setup
def get_db():
    db = sqlite3.connect('rbac.db')
    db.row_factory = sqlite3.Row
    return db

# def init_db():
#     with app.app_context():
#         db = get_db()
#         db.execute('CREATE TABLE IF NOT EXISTS users (id INTEGER PRIMARY KEY, username TEXT, password TEXT, role TEXT)')
#         db.execute('CREATE TABLE IF NOT EXISTS roles (id INTEGER PRIMARY KEY, name TEXT)')
#         # Add some default roles
#         db.execute('INSERT OR IGNORE INTO roles (name) VALUES (?)', ('admin',))
#         db.execute('INSERT OR IGNORE INTO roles (name) VALUES (?)', ('user',))
#         db.commit()

# init_db()
def init_db():
    with app.app_context():
        db = get_db()
        
        # Check if totp_secret column exists
        cursor = db.cursor()
        cursor.execute("PRAGMA table_info(users)")
        columns = [column[1] for column in cursor.fetchall()]
        
        if 'totp_secret' not in columns:
            # Add totp_secret column if it doesn't exist
            db.execute('ALTER TABLE users ADD COLUMN totp_secret TEXT')
        
        db.execute('CREATE TABLE IF NOT EXISTS users (id INTEGER PRIMARY KEY, username TEXT, password TEXT, role TEXT, totp_secret TEXT)')
        db.execute('CREATE TABLE IF NOT EXISTS roles (id INTEGER PRIMARY KEY, name TEXT)')
        # Add some default roles
        db.execute('INSERT OR IGNORE INTO roles (name) VALUES (?)', ('admin',))
        db.execute('INSERT OR IGNORE INTO roles (name) VALUES (?)', ('user',))
        db.commit()

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

# @app.route('/register', methods=['GET', 'POST'])
# def register():
#     if request.method == 'POST':
#         username = request.form['username']
#         password = request.form['password']
#         confirm_password = request.form['confirm_password']
#         role = 'user'  # Default role for new users

#         db = get_db()
#         user = db.execute('SELECT * FROM users WHERE username = ?', (username,)).fetchone()

#         if user:
#             flash('Username already exists', 'error')
#         elif password != confirm_password:
#             flash('Passwords do not match', 'error')
#         else:
#             hashed_password = generate_password_hash(password)
#             db.execute('INSERT INTO users (username, password, role) VALUES (?, ?, ?)',
#                        (username, hashed_password, role))
#             db.commit()
#             flash('Registration successful. Please log in.', 'success')
#             return redirect(url_for('login'))

#     return render_template('register.html')

# # Update the login route to use check_password_hash
# @app.route('/login', methods=['GET', 'POST'])
# def login():
#     if request.method == 'POST':
#         username = request.form['username']
#         password = request.form['password']
#         db = get_db()
#         user = db.execute('SELECT * FROM users WHERE username = ?', (username,)).fetchone()
#         if user and check_password_hash(user['password'], password):
#             session['user_id'] = user['id']
#             session['username'] = user['username']
#             session['role'] = user['role']
#             return redirect(url_for('dashboard'))
#         else:
#             flash('Invalid username or password', 'error')
#     return render_template('login.html')

def get_db():
    db = sqlite3.connect('rbac.db')
    db.row_factory = sqlite3.Row
    return db

def init_db():
    with app.app_context():
        db = get_db()
        
        # Check if totp_secret column exists
        cursor = db.cursor()
        cursor.execute("PRAGMA table_info(users)")
        columns = [column[1] for column in cursor.fetchall()]
        
        if 'totp_secret' not in columns:
            # Add totp_secret column if it doesn't exist
            db.execute('ALTER TABLE users ADD COLUMN totp_secret TEXT')
        db.execute('CREATE TABLE IF NOT EXISTS users (id INTEGER PRIMARY KEY, username TEXT UNIQUE, password TEXT, role TEXT, totp_secret TEXT)')
        db.execute('CREATE TABLE IF NOT EXISTS roles (id INTEGER PRIMARY KEY, name TEXT UNIQUE)')
        db.execute('''CREATE TABLE IF NOT EXISTS api_endpoints (
            id INTEGER PRIMARY KEY,
            name TEXT UNIQUE,
            endpoint TEXT UNIQUE,
            method TEXT,
            description TEXT
        )''')
        # Add default roles if they don't exist
        db.execute('INSERT OR IGNORE INTO roles (name) VALUES (?)', ('admin',))
        db.execute('INSERT OR IGNORE INTO roles (name) VALUES (?)', ('user',))
        db.commit()

init_db()


@app.route('/register', methods=['GET', 'POST'])
def register():
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']
        confirm_password = request.form['confirm_password']
        totp_code = request.form['totp_code']
        totp_secret = request.form['totp_secret']  # Get the secret from the form
        role = 'user'  # Default role for new users

        db = get_db()
        user = db.execute('SELECT * FROM users WHERE username = ?', (username,)).fetchone()

        if user:
            flash('Username already exists', 'error')
        elif password != confirm_password:
            flash('Passwords do not match', 'error')
        else:
            totp = pyotp.TOTP(totp_secret)
            if totp.verify(totp_code):
                hashed_password = generate_password_hash(password)
                db.execute('INSERT INTO users (username, password, role, totp_secret) VALUES (?, ?, ?, ?)',
                           (username, hashed_password, role, totp_secret))
                db.commit()
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
    
    # Round the corners
    img = img.convert("RGBA")
    width, height = img.size
    mask = Image.new('L', (width, height), 0)
    draw = ImageDraw.Draw(mask)
    draw.rounded_rectangle((0, 0, width, height), radius=20, fill=255)
    img.putalpha(mask)
    
    img = img.resize((200, 200))  # Resize to 200x200
    
    buffered = io.BytesIO()
    img.save(buffered, format="PNG")
    img_str = base64.b64encode(buffered.getvalue()).decode()

    return jsonify({'qr_code': img_str, 'totp_secret': totp_secret})

# @app.route('/register', methods=['GET', 'POST'])
# def register():
#     if request.method == 'POST':
#         username = request.form['username']
#         password = request.form['password']
#         confirm_password = request.form['confirm_password']
#         totp_code = request.form['totp_code']
#         role = 'user'  # Default role for new users

#         db = get_db()
#         user = db.execute('SELECT * FROM users WHERE username = ?', (username,)).fetchone()

#         if user:
#             flash('Username already exists', 'error')
#         elif password != confirm_password:
#             flash('Passwords do not match', 'error')
#         else:
#             totp_secret = session.get('totp_secret')
#             totp = pyotp.TOTP(totp_secret)
#             if totp.verify(totp_code):
#                 hashed_password = generate_password_hash(password)
#                 db.execute('INSERT INTO users (username, password, role, totp_secret) VALUES (?, ?, ?, ?)',
#                            (username, hashed_password, role, totp_secret))
#                 db.commit()
#                 flash('Registration successful. Please log in.', 'success')
#                 return redirect(url_for('login'))
#             else:
#                 flash('Invalid TOTP code', 'error')

#     return render_template('register.html')

# @app.route('/generate_qr', methods=['POST'])
# def generate_qr():
#     username = request.form['username']
#     totp_secret = pyotp.random_base32()
#     totp_uri = pyotp.totp.TOTP(totp_secret).provisioning_uri(name=username, issuer_name="ZTI_KARE")
    
#     qr = qrcode.QRCode(version=1, box_size=10, border=5)
#     qr.add_data(totp_uri)
#     qr.make(fit=True)
#     img = qr.make_image(fill_color="black", back_color="white")
    
#     # Round the corners
#     img = img.convert("RGBA")
#     width, height = img.size
#     mask = Image.new('L', (width, height), 0)
#     draw = ImageDraw.Draw(mask)
#     draw.rounded_rectangle((0, 0, width, height), radius=20, fill=255)
#     img.putalpha(mask)
    
#     img = img.resize((200, 200))  # Resize to 200x200
    
#     buffered = io.BytesIO()
#     img.save(buffered, format="PNG")
#     img_str = base64.b64encode(buffered.getvalue()).decode()

#     return {'qr_code': img_str, 'totp_secret': totp_secret}
# # @app.route('/register', methods=['GET', 'POST'])
# def register():
#     if request.method == 'POST':
#         username = request.form['username']
#         password = request.form['password']
#         confirm_password = request.form['confirm_password']
#         totp_code = request.form['totp_code']
#         role = 'user'  # Default role for new users

#         db = get_db()
#         user = db.execute('SELECT * FROM users WHERE username = ?', (username,)).fetchone()

#         if user:
#             flash('Username already exists', 'error')
#         elif password != confirm_password:
#             flash('Passwords do not match', 'error')
#         else:
#             totp_secret = session.get('totp_secret')
#             totp = pyotp.TOTP(totp_secret)
#             if totp.verify(totp_code):
#                 hashed_password = generate_password_hash(password)
#                 db.execute('INSERT INTO users (username, password, role, totp_secret) VALUES (?, ?, ?, ?)',
#                            (username, hashed_password, role, totp_secret))
#                 db.commit()
#                 flash('Registration successful. Please log in.', 'success')
#                 return redirect(url_for('login'))
#             else:
#                 flash('Invalid TOTP code', 'error')

#     totp_secret = pyotp.random_base32()
#     session['totp_secret'] = totp_secret
#     totp_uri = pyotp.totp.TOTP(totp_secret).provisioning_uri(name=request.form.get('username', 'user'), issuer_name="YourApp")
    
#     qr = qrcode.QRCode(version=1, box_size=10, border=5)
#     qr.add_data(totp_uri)
#     qr.make(fit=True)
#     img = qr.make_image(fill_color="black", back_color="white")
    
#     # Round the corners
#     img = img.convert("RGBA")
#     width, height = img.size
#     mask = Image.new('L', (width, height), 0)
#     draw = ImageDraw.Draw(mask)
#     draw.rounded_rectangle((0, 0, width, height), radius=20, fill=255)
#     img.putalpha(mask)
    
#     img = img.resize((200, 200))  # Resize to 200x200
    
#     buffered = io.BytesIO()
#     img.save(buffered, format="PNG")
#     img_str = base64.b64encode(buffered.getvalue()).decode()

#     return render_template('register.html', qr_code=img_str)

@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']
        totp_code = request.form['totp_code']
        db = get_db()
        user = db.execute('SELECT * FROM users WHERE username = ?', (username,)).fetchone()
        if user and check_password_hash(user['password'], password):
            totp = pyotp.TOTP(user['totp_secret'])
            if totp.verify(totp_code):
                session['user_id'] = user['id']
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
    db = get_db()
    user_role = session.get('role')

    if user_role == 'admin' and request.method == 'POST':
        action = request.form.get('action')
        
        if action == 'create_endpoint':
            name = request.form.get('name')
            endpoint = request.form.get('endpoint')
            method = request.form.get('method')
            description = request.form.get('description')
            
            try:
                db.execute('INSERT INTO api_endpoints (name, endpoint, method, description) VALUES (?, ?, ?, ?)',
                           (name, endpoint, method, description))
                db.commit()
                flash('API endpoint created successfully', 'success')
            except sqlite3.IntegrityError:
                flash('API endpoint with this name or URL already exists', 'error')
        
        elif action == 'delete_endpoint':
            endpoint_id = request.form.get('endpoint_id')
            db.execute('DELETE FROM api_endpoints WHERE id = ?', (endpoint_id,))
            db.commit()
            flash('API endpoint deleted successfully', 'success')
        
        elif action == 'change_role':
            user_id = request.form.get('user_id')
            new_role = request.form.get('new_role')
            db.execute('UPDATE users SET role = ? WHERE id = ?', (new_role, user_id))
            db.commit()
            flash('User role updated successfully', 'success')

    if user_role == 'admin':
        users = db.execute('SELECT id, username, role FROM users').fetchall()
        roles = db.execute('SELECT name FROM roles').fetchall()
        api_endpoints = db.execute('SELECT * FROM api_endpoints').fetchall()
    else:
        users = roles = api_endpoints = None

    return render_template('dashboard.html', user_role=user_role, users=users, roles=roles, api_endpoints=api_endpoints)

# @app.route('/admin')
# @login_required
# @role_required('admin')
# def admin():
#     db = get_db()
#     users = db.execute('SELECT id, username, role FROM users').fetchall()
#     roles = db.execute('SELECT name FROM roles').fetchall()
#     return render_template('admin.html', users=users, roles=roles)

# @app.route('/admin/change_role', methods=['POST'])
# @login_required
# @role_required('admin')
# def change_role():
#     user_id = request.form['user_id']
#     new_role = request.form['new_role']
#     admin_password = request.form['admin_password']

#     db = get_db()
#     admin = db.execute('SELECT * FROM users WHERE id = ?', (session['user_id'],)).fetchone()

#     if check_password_hash(admin['password'], admin_password):
#         db.execute('UPDATE users SET role = ? WHERE id = ?', (new_role, user_id))
#         db.commit()
#         flash('User role updated successfully', 'success')
#     else:
#         flash('Invalid admin password', 'error')

#     return redirect(url_for('admin'))

# @app.route('/admin/create_role', methods=['POST'])
# @login_required
# @role_required('admin')
# def create_role():
#     new_role = request.form['new_role']
#     admin_password = request.form['admin_password']

#     db = get_db()
#     admin = db.execute('SELECT * FROM users WHERE id = ?', (session['user_id'],)).fetchone()

#     if check_password_hash(admin['password'], admin_password):
#         db.execute('INSERT INTO roles (name) VALUES (?)', (new_role,))
#         db.commit()
#         flash('New role created successfully', 'success')
#     else:
#         flash('Invalid admin password', 'error')

#     return redirect(url_for('admin'))


# @app.route('/admin', methods=['GET'])
# @login_required
# @role_required('admin')
# def admin():
#     search_query = request.args.get('search', '')
#     db = get_db()
#     if search_query:
#         users = db.execute('SELECT id, username, role FROM users WHERE username LIKE ?', ('%' + search_query + '%',)).fetchall()
#     else:
#         users = db.execute('SELECT id, username, role FROM users').fetchall()
#     roles = db.execute('SELECT name FROM roles').fetchall()
#     return render_template('admin.html', users=users, roles=roles, search_query=search_query)

@app.route('/generate_qr_for_user', methods=['POST'])
@login_required
@role_required('admin')
def generate_qr_for_user():
    username = request.form['username']
    db = get_db()
    user = db.execute('SELECT totp_secret FROM users WHERE username = ?', (username,)).fetchone()
    
    if user:
        totp_secret = user['totp_secret']
        totp_uri = pyotp.totp.TOTP(totp_secret).provisioning_uri(name=username, issuer_name="YourApp")
        
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
        
        return jsonify({'qr_code': img_str})
    else:
        return jsonify({'error': 'User not found'}), 404

@app.route('/check_username', methods=['POST'])
@login_required
@role_required('admin')
def check_username():
    data = request.get_json()
    username = data.get('username')
    db = get_db()
    existing_user = db.execute('SELECT * FROM users WHERE username = ?', (username,)).fetchone()
    return jsonify({'exists': existing_user is not None})

# @app.route('/admin', methods=['GET', 'POST'])
# @login_required
# @role_required('admin')
# def admin():
    # db = get_db()
    # search_query = request.args.get('search', '')

    # if request.method == 'POST':
    #     if 'create_user' in request.form:
    #         # Create new user
    #         username = request.form['username']
    #         password = request.form['password']
    #         role = request.form['role']
    #         totp_secret = pyotp.random_base32()

    #         hashed_password = generate_password_hash(password)
    #         try:
    #             db.execute('INSERT INTO users (username, password, role, totp_secret) VALUES (?, ?, ?, ?)',
    #                        (username, hashed_password, role, totp_secret))
    #             db.commit()
    #             flash('New user created successfully', 'success')
    #         except sqlite3.IntegrityError:
    #             flash('Username already exists', 'error')

    #     elif 'purge_roles' in request.form:
    #         # Purge duplicate roles
    #         db.execute('''
    #             DELETE FROM roles
    #             WHERE id NOT IN (
    #                 SELECT MIN(id)
    #                 FROM roles
    #                 GROUP BY name
    #             )
    #         ''')
    #         db.commit()
    #         flash('Duplicate roles purged successfully', 'success')

    # if search_query:
    #     users = db.execute('SELECT id, username, role FROM users WHERE username LIKE ?', ('%' + search_query + '%',)).fetchall()
    # else:
    #     users = db.execute('SELECT id, username, role FROM users').fetchall()
    
    # roles = db.execute('SELECT name FROM roles').fetchall()
    # return render_template('admin.html', users=users, roles=roles, search_query=search_query)

@app.route('/admin', methods=['GET', 'POST'])
@login_required
@role_required('admin')
def admin():
    db = get_db()
    search_query = request.args.get('search', '')

    if request.method == 'POST':
        data = request.get_json()
        if data and data.get('action') == 'create_user':
            username = data.get('username')
            password = data.get('password')
            role = data.get('role')
            admin_password = data.get('admin_password')

            # Verify admin password
            admin_user = db.execute('SELECT * FROM users WHERE id = ?', (session['user_id'],)).fetchone()
            if not check_password_hash(admin_user['password'], admin_password):
                return jsonify({'status': 'error', 'message': 'Invalid admin password.'})

            # Check if username already exists
            existing_user = db.execute('SELECT * FROM users WHERE username = ?', (username,)).fetchone()
            if existing_user:
                return jsonify({'status': 'error', 'message': 'Username already exists. Please choose a different username.'})
            
            totp_secret = pyotp.random_base32()
            hashed_password = generate_password_hash(password)
            try:
                db.execute('INSERT INTO users (username, password, role, totp_secret) VALUES (?, ?, ?, ?)',
                           (username, hashed_password, role, totp_secret))
                db.commit()
                return jsonify({'status': 'success', 'message': 'New user created successfully'})
            except sqlite3.IntegrityError:
                return jsonify({'status': 'error', 'message': 'An error occurred while creating the user.'})

        # ... (handle other POST actions like purge_roles and create_role)

    # Handle GET request
    if search_query:
        users = db.execute('SELECT id, username, role FROM users WHERE username LIKE ?', ('%' + search_query + '%',)).fetchall()
    else:
        users = db.execute('SELECT id, username, role FROM users').fetchall()
    
    roles = db.execute('SELECT name FROM roles').fetchall()
    return render_template('admin.html', users=users, roles=roles, search_query=search_query)

@app.route('/admin/change_role', methods=['POST'])
@login_required
@role_required('admin')
def change_role():
    user_id = request.form['user_id']
    new_role = request.form['new_role']
    admin_password = request.form['admin_password']

    db = get_db()
    admin = db.execute('SELECT * FROM users WHERE id = ?', (session['user_id'],)).fetchone()

    if check_password_hash(admin['password'], admin_password):
        db.execute('UPDATE users SET role = ? WHERE id = ?', (new_role, user_id))
        db.commit()
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

    db = get_db()
    admin = db.execute('SELECT * FROM users WHERE id = ?', (session['user_id'],)).fetchone()

    if check_password_hash(admin['password'], admin_password):
        db.execute('INSERT INTO roles (name) VALUES (?)', (new_role,))
        db.commit()
        flash('New role created successfully', 'success')
    else:
        flash('Invalid admin password', 'error')

    return redirect(url_for('admin'))

if __name__ == '__main__':
    app.run(debug=True)