from flask import Flask, render_template, request, jsonify, session, redirect, url_for
import sqlite3
from PIL import Image
import io
import os
from functools import wraps
from werkzeug.security import generate_password_hash, check_password_hash
from transformers import BlipProcessor, BlipForConditionalGeneration
from authlib.integrations.flask_client import OAuth
import os
from dotenv import load_dotenv

# Ye line .env file se saare passwords load kar legi
load_dotenv()

os.environ['OAUTHLIB_INSECURE_TRANSPORT'] = '1'

app = Flask(__name__)
app.secret_key = "super_secret_key_for_session" 

# --- OAUTH SETUP ---
oauth = OAuth(app)
google = oauth.register(
    name='google',
    client_id=os.getenv('GOOGLE_CLIENT_ID'),       
    client_secret=os.getenv('GOOGLE_CLIENT_SECRET'),
    server_metadata_url='https://accounts.google.com/.well-known/openid-configuration',
    client_kwargs={'scope': 'openid email profile'}
)

github = oauth.register(
    name='github',
    client_id=os.getenv('GITHUB_CLIENT_ID'),       
    client_secret=os.getenv('GITHUB_CLIENT_SECRET'),
    access_token_url='https://github.com/login/oauth/access_token',
    authorize_url='https://github.com/login/oauth/authorize',
    api_base_url='https://api.github.com/',
    client_kwargs={'scope': 'user:email'},
)

# --- AI MODEL SETUP ---
print("Loading AI Model... Please wait.")
processor = BlipProcessor.from_pretrained("Salesforce/blip-image-captioning-base")
model = BlipForConditionalGeneration.from_pretrained("Salesforce/blip-image-captioning-base")
print("AI Model Loaded Successfully!")

# --- DATABASE SETUP ---
def get_db_connection():
    conn = sqlite3.connect('users.db', check_same_thread=False)
    conn.row_factory = sqlite3.Row
    return conn

with get_db_connection() as conn:
    conn.execute('''
        CREATE TABLE IF NOT EXISTS userstable(
            name TEXT, 
            email TEXT UNIQUE, 
            password TEXT, 
            status TEXT DEFAULT 'ACTIVE'
        )
    ''')
    conn.execute('CREATE TABLE IF NOT EXISTS historytable(email TEXT, result TEXT, timestamp DATETIME DEFAULT CURRENT_TIMESTAMP)')
    conn.commit()

# --- SECURITY MIDDLEWARE ---
@app.after_request
def add_header(response):
    response.headers['Cache-Control'] = 'no-store, no-cache, must-revalidate, post-check=0, pre-check=0, max-age=0'
    response.headers['Pragma'] = 'no-cache'
    response.headers['Expires'] = '-1'
    return response

def login_required(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if 'email' not in session:
            return redirect(url_for('home'))
        
        conn = get_db_connection()
        cur = conn.cursor()
        cur.execute('SELECT * FROM userstable WHERE email = ?', (session['email'],))
        user = cur.fetchone()
        
        # 🛠️ NAYA: Agar user nahi hai ya BLOCKED hai, toh bahar nikal do
        if not user or user['status'] == 'BLOCKED':
            session.pop('email', None)
            return redirect(url_for('home'))
            
        return f(*args, **kwargs)
    return decorated_function

# --- ROUTES ---
@app.route('/')
def home():
    if 'email' in session:
        conn = get_db_connection()
        cur = conn.cursor()
        cur.execute('SELECT * FROM userstable WHERE email = ?', (session['email'],))
        user = cur.fetchone()
        
        # 🛠️ NAYA: Agar user logged in hai lekin BLOCKED hai, toh home page pe hi rakho
        if user and user['status'] == 'ACTIVE':
            return redirect(url_for('dashboard'))
        else:
            session.pop('email', None)
            
    return render_template('login.html')

@app.route('/auth', methods=['POST'])
def auth():
    data = request.get_json()
    action = data.get('action')
    name = data.get('name') 
    email = data.get('email')
    password = data.get('password')

    conn = get_db_connection()
    cur = conn.cursor()

    if action == 'signup':
        # 🛠️ NAYA: Password length validation
        if len(password) < 8:
            return jsonify({"status": "error", "message": "Password must be at least 8 characters long!"}), 400

        # Pehle check karein ki kya email pehle se database mein hai?
        cur.execute('SELECT * FROM userstable WHERE email = ?', (email,))
        if cur.fetchone():
            return jsonify({"status": "error", "message": "Email already registered! Please login."}), 400

        # Baaki ka code same rahega...
        hashed_password = generate_password_hash(password)
        try:
            cur.execute('INSERT INTO userstable (name, email, password, status) VALUES (?, ?, ?, ?)', (name, email, hashed_password, 'ACTIVE'))
            conn.commit()
            session['email'] = email
            return jsonify({"status": "success"})
        except sqlite3.IntegrityError:
            return jsonify({"status": "error", "message": "Email already exists in Database."}), 400
        except Exception:
            return jsonify({"status": "error", "message": "Signup failed."}), 500
    
    elif action == 'login':
        cur.execute('SELECT * FROM userstable WHERE email = ?', (email,))
        user = cur.fetchone()
        
        if user:
            # 🛠️ NAYA: Blocked Check
            if user['status'] == 'BLOCKED':
                return jsonify({"status": "error", "message": "Your account has been BLOCKED. Contact admin."}), 403
                
            if user['password'] != 'OAUTH_USER' and check_password_hash(user['password'], password):
                session['email'] = email
                return jsonify({"status": "success"})
                
        return jsonify({"status": "error", "message": "Invalid email or password!"}), 401

# --- SOCIAL LOGIN CALLBACKS ---
@app.route('/login/google')
def login_google():
    redirect_uri = url_for('authorize_google', _external=True)
    return google.authorize_redirect(redirect_uri)

@app.route('/auth/google/callback')
def authorize_google():
    token = google.authorize_access_token()
    user_info = token.get('userinfo')
    name = user_info.get('name', user_info.get('given_name', 'Google User'))
    email = user_info.get('email')
    return handle_oauth_login(email, name)

@app.route('/login/github')
def login_github():
    redirect_uri = url_for('authorize_github', _external=True)
    return github.authorize_redirect(redirect_uri)

@app.route('/auth/github/callback')
def authorize_github():
    token = github.authorize_access_token()
    user_resp = github.get('user')
    user_data = user_resp.json()
    name = user_data.get('name', user_data.get('login', 'GitHub User'))
    
    emails_resp = github.get('user/emails')
    email = next(e['email'] for e in emails_resp.json() if e['primary'])
    return handle_oauth_login(email, name)

def handle_oauth_login(email, name):
    conn = get_db_connection()
    cur = conn.cursor()
    cur.execute('SELECT * FROM userstable WHERE email = ?', (email,))
    user = cur.fetchone()
    
    if user:
        # 🛠️ NAYA: Check if OAuth user is BLOCKED
        if user['status'] == 'BLOCKED':
            return "<h2 style='color:#ef4444; text-align:center; font-family:sans-serif; margin-top:50px;'>Access Denied: Your account has been blocked.</h2><center><a href='/' style='text-decoration:none; padding:10px 20px; background:#2563eb; color:white; border-radius:5px; font-family:sans-serif;'>Go to Login Page</a></center>", 403
    else:
        cur.execute('INSERT INTO userstable (name, email, password, status) VALUES (?, ?, ?, ?)', (name, email, 'OAUTH_USER', 'ACTIVE'))
        conn.commit()
        
    session['email'] = email
    return redirect(url_for('dashboard'))

# --- SECURE DASHBOARD ROUTE ---
@app.route('/dashboard')
@login_required 
def dashboard():
    conn = get_db_connection()
    cur = conn.cursor()
    
    cur.execute('SELECT * FROM userstable WHERE email = ?', (session['email'],))
    user = cur.fetchone()
    
    cur.execute('SELECT result, timestamp FROM historytable WHERE email = ? ORDER BY timestamp DESC', (session['email'],))
    user_history = cur.fetchall()
    
    first_name = user['name'].split()[0].capitalize()
    
    return render_template('dashboard.html', email=session['email'], history=user_history, username=first_name)

@app.route('/analyze', methods=['POST'])
@login_required 
def analyze():
    if 'image' not in request.files:
        return jsonify({"error": "No image uploaded"}), 400
        
    file = request.files['image']
    img = Image.open(file.stream).convert("RGB")
    
    inputs = processor(img, return_tensors="pt")
    out = model.generate(**inputs)
    result_text = processor.decode(out[0], skip_special_tokens=True).capitalize()
    
    conn = get_db_connection()
    cur = conn.cursor()
    cur.execute('INSERT INTO historytable (email, result) VALUES (?, ?)', (session['email'], result_text))
    conn.commit()
    
    import datetime
    current_time = datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    return jsonify({"result": result_text, "timestamp": current_time})

@app.route('/logout')
def logout():
    session.pop('email', None)
    return redirect(url_for('home'))

if __name__ == '__main__':
    app.run(debug=True, port=5000)