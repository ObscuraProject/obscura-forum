"""
Obscura Forum NO-JS Script - Main Flask Application WITH PROOF OF WORK GATEWAY (FIXED + SOLVER)
A fully functional forum system with role-based access, sub-forums (Sub-Scuras), no JavaScript, and PoW gateway
"""

from flask import Flask, render_template, request, redirect, url_for, session, flash
from werkzeug.security import generate_password_hash, check_password_hash
from datetime import datetime, timedelta
import sqlite3
import os
import hashlib
import secrets

app = Flask(__name__)
app.secret_key = 'your-secret-key-change-this-in-production'
DATABASE = 'forum.db'

# ===== PROOF OF WORK CONSTANTS =====
POW_DIFFICULTY = 8  # Number of leading zeros required in hash
POW_EXPIRY = 3600  # Proof of work valid for 1 hour (in seconds)

# ===== DATABASE FUNCTIONS =====

def get_db():
    """Get database connection"""
    db = sqlite3.connect(DATABASE)
    db.row_factory = sqlite3.Row
    return db

def init_db():
    """Initialize database with tables"""
    with app.app_context():
        db = get_db()
        cursor = db.cursor()
        
        # Users table
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS users (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                username TEXT UNIQUE NOT NULL,
                email TEXT UNIQUE NOT NULL,
                password TEXT NOT NULL,
                role TEXT DEFAULT 'standard_user',
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                is_active BOOLEAN DEFAULT 1,
                bio TEXT
            )
        ''')
        
        # Proof of Work table - tracks completed PoW challenges
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS pow_challenges (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                challenge_token TEXT UNIQUE NOT NULL,
                difficulty INTEGER NOT NULL,
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                completed_at TIMESTAMP,
                is_completed BOOLEAN DEFAULT 0,
                ip_address TEXT,
                verified_hash TEXT
            )
        ''')
        
        # Sub-Scuras (sub-forums) table
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS subscuras (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                name TEXT UNIQUE NOT NULL,
                description TEXT,
                creator_id INTEGER NOT NULL,
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                members_count INTEGER DEFAULT 0,
                FOREIGN KEY (creator_id) REFERENCES users(id)
            )
        ''')
        
        # Topics table
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS topics (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                title TEXT NOT NULL,
                content TEXT NOT NULL,
                author_id INTEGER NOT NULL,
                subscura_id INTEGER NOT NULL,
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                views INTEGER DEFAULT 0,
                is_pinned BOOLEAN DEFAULT 0,
                FOREIGN KEY (author_id) REFERENCES users(id),
                FOREIGN KEY (subscura_id) REFERENCES subscuras(id)
            )
        ''')
        
        # Posts/Replies table
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS posts (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                content TEXT NOT NULL,
                author_id INTEGER NOT NULL,
                topic_id INTEGER NOT NULL,
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                FOREIGN KEY (author_id) REFERENCES users(id),
                FOREIGN KEY (topic_id) REFERENCES topics(id)
            )
        ''')
        
        # Sub-Scura members table
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS subscura_members (
                subscura_id INTEGER NOT NULL,
                user_id INTEGER NOT NULL,
                joined_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                PRIMARY KEY (subscura_id, user_id),
                FOREIGN KEY (subscura_id) REFERENCES subscuras(id),
                FOREIGN KEY (user_id) REFERENCES users(id)
            )
        ''')
        
        db.commit()
        db.close()

# ===== PROOF OF WORK FUNCTIONS =====

def generate_pow_challenge():
    """Generate a new proof of work challenge token"""
    return secrets.token_hex(16)

def check_pow_hash(data, difficulty):
    """Check if a hash meets the proof of work difficulty requirement"""
    hash_obj = hashlib.sha256(data.encode())
    hash_hex = hash_obj.hexdigest()
    # Check if hash starts with required number of zeros
    return hash_hex.startswith('0' * difficulty), hash_hex

def verify_pow_solution(challenge_token, nonce, difficulty):
    """Verify that a proof of work solution is valid"""
    data = f"{challenge_token}:{nonce}"
    is_valid, hash_result = check_pow_hash(data, difficulty)
    return is_valid, hash_result

def get_client_ip():
    """Get client IP address"""
    if request.headers.get('X-Forwarded-For'):
        return request.headers.get('X-Forwarded-For').split(',')[0]
    return request.remote_addr

def mark_pow_complete(challenge_token, verified_hash):
    """Mark a proof of work challenge as completed"""
    db = get_db()
    db.execute('''
        UPDATE pow_challenges 
        SET is_completed = 1, completed_at = CURRENT_TIMESTAMP, verified_hash = ?
        WHERE challenge_token = ?
    ''', (verified_hash, challenge_token))
    db.commit()
    db.close()

def has_valid_pow_token(challenge_token):
    """Check if a user has a valid, non-expired proof of work token"""
    db = get_db()
    result = db.execute('''
        SELECT * FROM pow_challenges 
        WHERE challenge_token = ? AND is_completed = 1
    ''', (challenge_token,)).fetchone()
    
    if not result:
        db.close()
        return False
    
    # Check if token has expired
    completed_time = datetime.fromisoformat(result['completed_at'])
    if (datetime.now() - completed_time).total_seconds() > POW_EXPIRY:
        db.close()
        return False
    
    db.close()
    return True

# ===== HELPER FUNCTIONS =====

def get_user_by_username(username):
    """Get user by username"""
    db = get_db()
    user = db.execute('SELECT * FROM users WHERE username = ?', (username,)).fetchone()
    db.close()
    return user

def get_user_by_id(user_id):
    """Get user by ID"""
    db = get_db()
    user = db.execute('SELECT * FROM users WHERE id = ?', (user_id,)).fetchone()
    db.close()
    return user

def is_authenticated():
    """Check if user is authenticated"""
    return 'user_id' in session

def is_admin():
    """Check if current user is admin"""
    if not is_authenticated():
        return False
    user = get_user_by_id(session['user_id'])
    return user and user['role'] == 'admin'

def get_role_icon(role):
    """Return icon HTML for user role"""
    icons = {
        'admin': '👑 Admin',
        'staff': '🛡️ Staff',
        'verified_vendor': '✅ Vendor',
        'standard_vendor': '🏪 Vendor',
        'verified_user': '✔️ Verified',
        'standard_user': '👤',
        'verified_developer': '💻 Dev',
        'standard_developer': '⌨️ Dev'
    }
    return icons.get(role, '👤')

# ===== PROOF OF WORK ROUTES =====

@app.route('/pow', methods=['GET', 'POST'])
def proof_of_work_gateway():
    """Proof of work gateway - required to access forum - FIXED VERSION"""
    
    if request.method == 'POST':
        challenge_token = request.form.get('challenge_token')
        nonce = request.form.get('nonce', '')
        
        if not challenge_token or not nonce:
            flash('Missing challenge token or nonce', 'error')
            # Return to same challenge instead of generating new one
            return render_template('pow_gateway.html', 
                                  challenge_token=challenge_token if challenge_token else generate_pow_challenge(),
                                  difficulty=POW_DIFFICULTY)
        
        # Verify the proof of work
        is_valid, hash_result = verify_pow_solution(challenge_token, nonce, POW_DIFFICULTY)
        
        if not is_valid:
            flash('Invalid proof of work. Please try again with the same challenge.', 'error')
            # Keep the same challenge token on failure
            return render_template('pow_gateway.html', 
                                  challenge_token=challenge_token,
                                  difficulty=POW_DIFFICULTY)
        
        # Mark the challenge as completed
        mark_pow_complete(challenge_token, hash_result)
        
        # Store in session that user has completed PoW
        session['pow_token'] = challenge_token
        session['pow_verified'] = True
        
        flash('Proof of work verified! Welcome to Obscura Forum.', 'success')
        return redirect(url_for('index'))
    
    # GET request - generate new challenge
    challenge_token = generate_pow_challenge()
    
    db = get_db()
    db.execute('''
        INSERT INTO pow_challenges (challenge_token, difficulty, ip_address)
        VALUES (?, ?, ?)
    ''', (challenge_token, POW_DIFFICULTY, get_client_ip()))
    db.commit()
    db.close()
    
    return render_template('pow_gateway.html', 
                          challenge_token=challenge_token,
                          difficulty=POW_DIFFICULTY)

@app.route('/pow/solve', methods=['POST'])
def solve_pow_challenge():
    """Server-side PoW solver - solves the challenge and returns nonce"""
    challenge_token = request.form.get('challenge_token')
    difficulty = int(request.form.get('difficulty', POW_DIFFICULTY))
    
    if not challenge_token:
        flash('Missing challenge token', 'error')
        return redirect(url_for('proof_of_work_gateway'))
    
    # Solve the proof of work challenge
    nonce = 0
    max_attempts = 10000000  # Limit to prevent infinite loop
    
    while nonce < max_attempts:
        data = f"{challenge_token}:{nonce}"
        hash_obj = hashlib.sha256(data.encode())
        hash_hex = hash_obj.hexdigest()
        
        # Check if hash meets difficulty
        if hash_hex.startswith('0' * difficulty):
            # Found solution! Return to gateway with nonce pre-filled
            flash(f'Solution found! Nonce: {nonce}', 'success')
            return render_template('pow_gateway.html',
                                 challenge_token=challenge_token,
                                 difficulty=difficulty,
                                 solved_nonce=nonce)
        
        nonce += 1
    
    # Failed to find solution
    flash('Failed to find solution within reasonable time. Try again.', 'error')
    return render_template('pow_gateway.html',
                         challenge_token=challenge_token,
                         difficulty=difficulty)

def require_pow(f):
    """Decorator to require proof of work before accessing a route"""
    def decorated_function(*args, **kwargs):
        # Check if user has completed PoW
        pow_token = session.get('pow_token')
        pow_verified = session.get('pow_verified', False)
        
        if not pow_verified or not has_valid_pow_token(pow_token):
            return redirect(url_for('proof_of_work_gateway'))
        
        return f(*args, **kwargs)
    
    decorated_function.__name__ = f.__name__
    return decorated_function

# ===== AUTHENTICATION ROUTES =====

@app.route('/register', methods=['GET', 'POST'])
@require_pow
def register():
    """Register a new user"""
    if request.method == 'POST':
        username = request.form.get('username')
        email = request.form.get('email')
        password = request.form.get('password')
        
        if not username or not email or not password:
            flash('All fields are required', 'error')
            return redirect(url_for('register'))
        
        db = get_db()
        try:
            db.execute(
                'INSERT INTO users (username, email, password, role) VALUES (?, ?, ?, ?)',
                (username, email, generate_password_hash(password), 'standard_user')
            )
            db.commit()
            flash('Registration successful! Please log in.', 'success')
            return redirect(url_for('login'))
        except sqlite3.IntegrityError:
            flash('Username or email already exists', 'error')
        finally:
            db.close()
    
    return render_template('register.html')

@app.route('/login', methods=['GET', 'POST'])
@require_pow
def login():
    """Login user"""
    if request.method == 'POST':
        username = request.form.get('username')
        password = request.form.get('password')
        
        user = get_user_by_username(username)
        
        if user and check_password_hash(user['password'], password):
            if user['is_active']:
                session['user_id'] = user['id']
                session['username'] = user['username']
                session['role'] = user['role']
                flash('Login successful!', 'success')
                return redirect(url_for('index'))
            else:
                flash('Your account has been disabled', 'error')
        else:
            flash('Invalid credentials', 'error')
    
    return render_template('login.html')

@app.route('/logout')
def logout():
    """Logout user"""
    session.clear()
    flash('You have been logged out', 'success')
    return redirect(url_for('proof_of_work_gateway'))

# ===== MAIN ROUTES =====

@app.route('/')
@require_pow
def index():
    """Home page - list all sub-scuras"""
    db = get_db()
    subscuras = db.execute('SELECT * FROM subscuras ORDER BY created_at DESC').fetchall()
    db.close()
    return render_template('index.html', subscuras=subscuras)

@app.route('/subscura/<int:subscura_id>')
@require_pow
def subscura_detail(subscura_id):
    """View a specific sub-scura"""
    db = get_db()
    subscura = db.execute('SELECT * FROM subscuras WHERE id = ?', (subscura_id,)).fetchone()
    
    if not subscura:
        flash('Sub-Scura not found', 'error')
        return redirect(url_for('index'))
    
    topics = db.execute('''
        SELECT t.*, u.username, u.role, COUNT(p.id) as reply_count
        FROM topics t
        JOIN users u ON t.author_id = u.id
        LEFT JOIN posts p ON t.id = p.topic_id
        WHERE t.subscura_id = ?
        GROUP BY t.id
        ORDER BY t.is_pinned DESC, t.created_at DESC
    ''', (subscura_id,)).fetchall()
    
    db.close()
    return render_template('subscura_detail.html', subscura=subscura, topics=topics, get_role_icon=get_role_icon)

@app.route('/subscura/new', methods=['GET', 'POST'])
@require_pow
def create_subscura():
    """Create a new sub-scura"""
    if not is_authenticated():
        flash('You must be logged in', 'error')
        return redirect(url_for('login'))
    
    if request.method == 'POST':
        name = request.form.get('name')
        description = request.form.get('description')
        
        if not name:
            flash('Sub-Scura name is required', 'error')
            return redirect(url_for('create_subscura'))
        
        db = get_db()
        try:
            db.execute(
                'INSERT INTO subscuras (name, description, creator_id) VALUES (?, ?, ?)',
                (name, description, session['user_id'])
            )
            db.execute(
                'INSERT INTO subscura_members (subscura_id, user_id) VALUES ((SELECT id FROM subscuras WHERE name = ?), ?)',
                (name, session['user_id'])
            )
            db.commit()
            flash('Sub-Scura created successfully!', 'success')
            return redirect(url_for('index'))
        except sqlite3.IntegrityError:
            flash('Sub-Scura name already exists', 'error')
        finally:
            db.close()
    
    return render_template('create_subscura.html')

@app.route('/topic/<int:topic_id>')
@require_pow
def topic_detail(topic_id):
    """View a specific topic with all replies"""
    db = get_db()
    topic = db.execute('''
        SELECT t.*, u.username, u.role
        FROM topics t
        JOIN users u ON t.author_id = u.id
        WHERE t.id = ?
    ''', (topic_id,)).fetchone()
    
    if not topic:
        flash('Topic not found', 'error')
        return redirect(url_for('index'))
    
    posts = db.execute('''
        SELECT p.*, u.username, u.role
        FROM posts p
        JOIN users u ON p.author_id = u.id
        WHERE p.topic_id = ?
        ORDER BY p.created_at ASC
    ''', (topic_id,)).fetchall()
    
    # Increment view count
    db.execute('UPDATE topics SET views = views + 1 WHERE id = ?', (topic_id,))
    db.commit()
    db.close()
    
    return render_template('topic_detail.html', topic=topic, posts=posts, get_role_icon=get_role_icon)

@app.route('/topic/new/<int:subscura_id>', methods=['GET', 'POST'])
@require_pow
def create_topic(subscura_id):
    """Create a new topic"""
    if not is_authenticated():
        flash('You must be logged in', 'error')
        return redirect(url_for('login'))
    
    db = get_db()
    subscura = db.execute('SELECT * FROM subscuras WHERE id = ?', (subscura_id,)).fetchone()
    
    if not subscura:
        flash('Sub-Scura not found', 'error')
        db.close()
        return redirect(url_for('index'))
    
    if request.method == 'POST':
        title = request.form.get('title')
        content = request.form.get('content')
        
        if not title or not content:
            flash('Title and content are required', 'error')
            return redirect(url_for('create_topic', subscura_id=subscura_id))
        
        db.execute(
            'INSERT INTO topics (title, content, author_id, subscura_id) VALUES (?, ?, ?, ?)',
            (title, content, session['user_id'], subscura_id)
        )
        db.commit()
        flash('Topic created successfully!', 'success')
        db.close()
        return redirect(url_for('subscura_detail', subscura_id=subscura_id))
    
    db.close()
    return render_template('create_topic.html', subscura=subscura)

@app.route('/post/<int:topic_id>', methods=['POST'])
@require_pow
def create_post(topic_id):
    """Create a reply to a topic"""
    if not is_authenticated():
        flash('You must be logged in', 'error')
        return redirect(url_for('login'))
    
    content = request.form.get('content')
    
    if not content:
        flash('Post content is required', 'error')
        return redirect(url_for('topic_detail', topic_id=topic_id))
    
    db = get_db()
    db.execute(
        'INSERT INTO posts (content, author_id, topic_id) VALUES (?, ?, ?)',
        (content, session['user_id'], topic_id)
    )
    db.commit()
    db.close()
    
    flash('Reply posted successfully!', 'success')
    return redirect(url_for('topic_detail', topic_id=topic_id))

# ===== ADMIN ROUTES =====

@app.route('/admin')
@require_pow
def admin_panel():
    """Admin dashboard"""
    if not is_admin():
        flash('Access denied', 'error')
        return redirect(url_for('index'))
    
    db = get_db()
    users = db.execute('SELECT * FROM users ORDER BY created_at DESC').fetchall()
    topics = db.execute('SELECT * FROM topics ORDER BY created_at DESC LIMIT 10').fetchall()
    db.close()
    
    return render_template('admin_panel.html', users=users, topics=topics, get_role_icon=get_role_icon)

@app.route('/admin/user/<int:user_id>/role', methods=['POST'])
@require_pow
def update_user_role(user_id):
    """Update user role"""
    if not is_admin():
        flash('Access denied', 'error')
        return redirect(url_for('index'))
    
    role = request.form.get('role')
    valid_roles = ['admin', 'staff', 'verified_vendor', 'standard_vendor', 'verified_user', 'standard_user', 'verified_developer', 'standard_developer']
    
    if role not in valid_roles:
        flash('Invalid role', 'error')
        return redirect(url_for('admin_panel'))
    
    db = get_db()
    db.execute('UPDATE users SET role = ? WHERE id = ?', (role, user_id))
    db.commit()
    db.close()
    
    flash('User role updated', 'success')
    return redirect(url_for('admin_panel'))

@app.route('/admin/user/<int:user_id>/toggle', methods=['POST'])
@require_pow
def toggle_user_status(user_id):
    """Enable/disable user account"""
    if not is_admin():
        flash('Access denied', 'error')
        return redirect(url_for('index'))
    
    db = get_db()
    user = db.execute('SELECT is_active FROM users WHERE id = ?', (user_id,)).fetchone()
    
    if user:
        db.execute('UPDATE users SET is_active = ? WHERE id = ?', (not user['is_active'], user_id))
        db.commit()
        flash('User status updated', 'success')
    
    db.close()
    return redirect(url_for('admin_panel'))

@app.route('/admin/post/<int:post_id>/delete', methods=['POST'])
@require_pow
def delete_post(post_id):
    """Delete a post"""
    if not is_admin():
        flash('Access denied', 'error')
        return redirect(url_for('index'))
    
    db = get_db()
    post = db.execute('SELECT topic_id FROM posts WHERE id = ?', (post_id,)).fetchone()
    
    if post:
        db.execute('DELETE FROM posts WHERE id = ?', (post_id,))
        db.commit()
        flash('Post deleted', 'success')
        db.close()
        return redirect(url_for('topic_detail', topic_id=post['topic_id']))
    
    db.close()
    return redirect(url_for('index'))

# ===== USER PROFILE ROUTES =====

@app.route('/user/<int:user_id>')
@require_pow
def user_profile(user_id):
    """View user profile"""
    db = get_db()
    user = db.execute('SELECT * FROM users WHERE id = ?', (user_id,)).fetchone()
    
    if not user:
        flash('User not found', 'error')
        db.close()
        return redirect(url_for('index'))
    
    posts_count_row = db.execute('SELECT COUNT(*) as count FROM posts WHERE author_id = ?', (user_id,)).fetchone()
    topics_count_row = db.execute('SELECT COUNT(*) as count FROM topics WHERE author_id = ?', (user_id,)).fetchone()
    
    posts_count = posts_count_row['count'] if posts_count_row else 0
    topics_count = topics_count_row['count'] if topics_count_row else 0
    
    db.close()
    
    return render_template('user_profile.html', 
                          user=user, 
                          posts_count=posts_count, 
                          topics_count=topics_count,
                          get_role_icon=get_role_icon)

@app.route('/user/<int:user_id>/edit', methods=['GET', 'POST'])
@require_pow
def edit_profile(user_id):
    """Edit user profile - only allow users to edit their own profile"""
    if not is_authenticated():
        flash('You must be logged in', 'error')
        return redirect(url_for('login'))
    
    # Only allow users to edit their own profile
    if session['user_id'] != user_id:
        flash('You can only edit your own profile', 'error')
        return redirect(url_for('user_profile', user_id=user_id))
    
    db = get_db()
    user = db.execute('SELECT * FROM users WHERE id = ?', (user_id,)).fetchone()
    
    if not user:
        flash('User not found', 'error')
        db.close()
        return redirect(url_for('index'))
    
    if request.method == 'POST':
        bio = request.form.get('bio', '')
        
        # Optional: Update password if provided
        password = request.form.get('password')
        
        try:
            if password:
                # Hash the new password
                hashed_password = generate_password_hash(password)
                db.execute('UPDATE users SET bio = ?, password = ? WHERE id = ?', 
                          (bio, hashed_password, user_id))
            else:
                # Just update bio
                db.execute('UPDATE users SET bio = ? WHERE id = ?', (bio, user_id))
            
            db.commit()
            flash('Profile updated successfully!', 'success')
            db.close()
            return redirect(url_for('user_profile', user_id=user_id))
        except Exception as e:
            flash('Error updating profile', 'error')
            db.close()
            return redirect(url_for('edit_profile', user_id=user_id))
    
    db.close()
    return render_template('edit_profile.html', user=user)

if __name__ == '__main__':
    init_db()
    app.run(debug=False)
