from flask import Flask, render_template, request, redirect, session, url_for
from werkzeug.security import generate_password_hash, check_password_hash
import sqlite3
import os

app = Flask(__name__, static_url_path='/static', static_folder='static')
app.secret_key = 'supersecretkey'  # change this in production

# DB INIT
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
        conn.commit()

@app.route('/')
def index():
    return redirect('/login')

@app.route('/register', methods=['GET', 'POST'])
def register():
    if request.method == 'POST':
        name = request.form['name']
        email = request.form['email']
        password = generate_password_hash(request.form['password'])

        with sqlite3.connect('users.db') as conn:
            c = conn.cursor()
            try:
                c.execute("INSERT INTO users (name, email, password) VALUES (?, ?, ?)", 
                          (name, email, password))
                conn.commit()
                return redirect('/login')
            except:
                return "User already exists!"
    return render_template('register.html')

@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        email = request.form['email']
        password = request.form['password']

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

@app.route('/forgot', methods=['GET', 'POST'])
def forgot_password():
    if request.method == 'POST':
        email = request.form['email']
        with sqlite3.connect('users.db') as conn:
            c = conn.cursor()
            c.execute("SELECT * FROM users WHERE email=?", (email,))
            user = c.fetchone()
            if user:
                return redirect(url_for('reset_password', email=email))
            else:
                return "Email not found!"
    return render_template('forgot_password.html')

@app.route('/reset/<email>', methods=['GET', 'POST'])
def reset_password(email):
    if request.method == 'POST':
        new_pass = generate_password_hash(request.form['password'])
        with sqlite3.connect('users.db') as conn:
            c = conn.cursor()
            c.execute("UPDATE users SET password=? WHERE email=?", (new_pass, email))
            conn.commit()
            return redirect('/login')
    return render_template('reset_password.html', email=email)

@app.route('/dashboard')
def dashboard():
    if 'user_id' not in session:
        return redirect('/login')
    return render_template('dashboard.html', name=session['user_name'], profile_pic=session['profile_pic'])

@app.route('/logout')
def logout():
    session.clear()
    return redirect('/login')

if __name__ == '__main__':
    init_db()
    app.run(debug=True)