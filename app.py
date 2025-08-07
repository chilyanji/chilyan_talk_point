from flask import Flask, render_template, request, redirect, session, send_file, jsonify, url_for
from flask_socketio import SocketIO, emit, send
from werkzeug.security import generate_password_hash, check_password_hash
from werkzeug.utils import secure_filename
from itsdangerous import URLSafeTimedSerializer
import os
import sqlite3
from io import BytesIO
from reportlab.pdfgen import canvas
from reportlab.lib.pagesizes import letter
from datetime import datetime

# === App config ===
app = Flask(__name__, static_url_path='/static', static_folder='static')
app.secret_key = 'supersecretkey'
socketio = SocketIO(app, cors_allowed_origins="*")
serializer = URLSafeTimedSerializer(app.secret_key)

UPLOAD_FOLDER = 'static/uploads'
app.config['UPLOAD_FOLDER'] = UPLOAD_FOLDER

# ================== DB INIT =====================
def init_db():
    with sqlite3.connect('users.db') as conn:
        c = conn.cursor()
        c.execute('''CREATE TABLE IF NOT EXISTS users (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            name TEXT,
            email TEXT UNIQUE,
            password TEXT,
            profile_pic TEXT DEFAULT 'default.png'
        )''')
        c.execute('''CREATE TABLE IF NOT EXISTS messages (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            user_id INTEGER,
            message TEXT,
            timestamp TEXT,
            FOREIGN KEY (user_id) REFERENCES users(id)
        )''')
        conn.commit()

# ================== ROUTES =====================
@app.route("/")
def index():
    return redirect('/login')

@app.route('/register', methods=['GET', 'POST'])
def register():
    if request.method == 'POST':
        name = request.form.get('name')
        email = request.form.get('email')
        password = request.form.get('password')
        confirm = request.form.get('confirm_password')

        if not name or not email or not password or not confirm:
            return "All fields are required!"

        if password != confirm:
            return "Passwords do not match!"

        hashed = generate_password_hash(password)

        with sqlite3.connect('users.db') as conn:
            c = conn.cursor()
            try:
                c.execute("INSERT INTO users (name, email, password) VALUES (?, ?, ?)", 
                          (name, email, hashed))
                conn.commit()
                return redirect('/login')
            except sqlite3.IntegrityError:
                return "User already exists!"
            except Exception as e:
                return f"Error: {str(e)}"
    return render_template('register.html')

@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        email = request.form.get('email')
        password = request.form.get('password')
        with sqlite3.connect('users.db') as conn:
            c = conn.cursor()
            c.execute("SELECT * FROM users WHERE email=?", (email,))
            user = c.fetchone()
            if user and check_password_hash(user[3], password):
                session['user_id'] = user[0]
                session['user_name'] = user[1]
                session['profile_pic'] = user[4]
                return redirect('/dashboard')
            else:
                return "Invalid credentials!"
    return render_template('login.html')

@app.route('/dashboard')
def dashboard():
    if 'user_id' not in session:
        return redirect('/login')
    return render_template('dashboard.html', name=session['user_name'], profile_pic=session['profile_pic'])

@app.route('/upload', methods=['POST'])
def upload():
    if 'user_id' not in session:
        return redirect('/login')
    file = request.files.get('profile')
    if file and file.filename != '':
        filename = secure_filename(file.filename)
        path = os.path.join(app.config['UPLOAD_FOLDER'], filename)
        file.save(path)
        with sqlite3.connect('users.db') as conn:
            c = conn.cursor()
            c.execute("UPDATE users SET profile_pic=? WHERE id=?", (filename, session['user_id']))
            conn.commit()
        session['profile_pic'] = filename
    return redirect('/dashboard')

@app.route('/forgot', methods=['GET', 'POST'])
def forgot_password():
    if request.method == 'POST':
        email = request.form['email']
        token = serializer.dumps(email, salt='reset')
        reset_link = url_for('reset_password', token=token, _external=True)
        return f"<p>Reset link: <a href='{reset_link}'>{reset_link}</a></p>"
    return render_template('forgot_password.html')

@app.route('/reset/<token>', methods=['GET', 'POST'])
def reset_password(token):
    try:
        email = serializer.loads(token, salt='reset', max_age=3600)
    except:
        return "Invalid or expired link!"
    if request.method == 'POST':
        new = request.form['new_password']
        confirm = request.form['confirm_password']
        if new != confirm:
            return "Passwords do not match"
        hashed = generate_password_hash(new)
        with sqlite3.connect('users.db') as conn:
            c = conn.cursor()
            c.execute("UPDATE users SET password=? WHERE email=?", (hashed, email))
            conn.commit()
        return redirect('/login')
    return render_template('reset_password.html', email=email)

@app.route('/chat')
def chat():
    if 'user_id' not in session:
        return redirect('/login')
    return render_template('chat.html', name=session['user_name'])

@app.route('/send_message', methods=['POST'])
def send_message():
    if 'user_id' not in session:
        return 'Unauthorized', 401
    message = request.form['message']
    timestamp = datetime.now().strftime('%Y-%m-%d %H:%M:%S')
    with sqlite3.connect('users.db') as conn:
        c = conn.cursor()
        c.execute("INSERT INTO messages (user_id, message, timestamp) VALUES (?, ?, ?)",
                  (session['user_id'], message, timestamp))
        conn.commit()
    return 'OK'

@app.route('/get_messages')
def get_messages():
    with sqlite3.connect('users.db') as conn:
        c = conn.cursor()
        c.execute("SELECT users.name, messages.message, messages.timestamp FROM messages JOIN users ON users.id = messages.user_id ORDER BY messages.id DESC LIMIT 20")
        messages = c.fetchall()
    messages.reverse()
    return jsonify(messages)

@app.route('/export_chat')
def export_chat():
    if 'user_id' not in session:
        return redirect('/login')
    filename = f'chat_{session["user_id"]}.pdf'
    filepath = os.path.join('static', filename)
    c = canvas.Canvas(filepath, pagesize=letter)
    with sqlite3.connect('users.db') as conn:
        cur = conn.cursor()
        cur.execute("SELECT users.name, messages.message, messages.timestamp FROM messages JOIN users ON users.id = messages.user_id ORDER BY messages.id")
        messages = cur.fetchall()
    y = 750
    for name, msg, time in messages:
        c.drawString(50, y, f"[{time}] {name}: {msg}")
        y -= 20
        if y < 50:
            c.showPage()
            y = 750
    c.save()
    return send_file(filepath, as_attachment=True)

@app.route('/logout')
def logout():
    session.clear()
    return redirect('/login')

# Real-time chat
@socketio.on('message')
def handle_message(msg):
    print('Message:', msg)
    send(msg, broadcast=True)

# ========= Run =========
if __name__ == '__main__':
    os.makedirs('static/uploads', exist_ok=True)
    init_db()
    socketio.run(app, debug=True, port=10000, allow_unsafe_werkzeug=True)
