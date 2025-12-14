from flask import Flask, render_template, request, redirect, url_for, flash, session
import sqlite3
from datetime import datetime
import os
from werkzeug.security import generate_password_hash, check_password_hash
from werkzeug.utils import secure_filename
from PIL import Image
import secrets

app = Flask(__name__)
app.config.from_object('config.Config')
app.secret_key = app.config['SECRET_KEY']

ALLOWED_EXTENSIONS = {'png', 'jpg', 'jpeg', 'gif'}


def get_db():
    conn = sqlite3.connect(app.config['DATABASE'])
    conn.row_factory = sqlite3.Row
    return conn


def init_db():
    conn = get_db()
    c = conn.cursor()

    c.execute('''
        CREATE TABLE IF NOT EXISTS users (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            username TEXT UNIQUE NOT NULL,
            email TEXT UNIQUE NOT NULL,
            password_hash TEXT NOT NULL,
            bio TEXT DEFAULT '',
            avatar TEXT DEFAULT 'default.jpg',
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
        )
    ''')

    c.execute('''
        CREATE TABLE IF NOT EXISTS posts (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            content TEXT NOT NULL,
            user_id INTEGER NOT NULL,
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            FOREIGN KEY (user_id) REFERENCES users (id) ON DELETE CASCADE
        )
    ''')

    c.execute('''
        CREATE TABLE IF NOT EXISTS comments (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            content TEXT NOT NULL,
            user_id INTEGER NOT NULL,
            post_id INTEGER NOT NULL,
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            FOREIGN KEY (user_id) REFERENCES users (id) ON DELETE CASCADE,
            FOREIGN KEY (post_id) REFERENCES posts (id) ON DELETE CASCADE
        )
    ''')

    c.execute('''
        CREATE TABLE IF NOT EXISTS likes (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            user_id INTEGER NOT NULL,
            post_id INTEGER NOT NULL,
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            UNIQUE(user_id, post_id),
            FOREIGN KEY (user_id) REFERENCES users (id) ON DELETE CASCADE,
            FOREIGN KEY (post_id) REFERENCES posts (id) ON DELETE CASCADE
        )
    ''')

    conn.commit()
    conn.close()


def allowed_file(filename):
    return '.' in filename and filename.rsplit('.', 1)[1].lower() in ALLOWED_EXTENSIONS


def save_avatar(file):
    random_hex = secrets.token_hex(8)
    _, f_ext = os.path.splitext(file.filename)
    filename = random_hex + f_ext
    filepath = os.path.join(app.config['UPLOAD_FOLDER'], filename)

    output_size = (150, 150)
    i = Image.open(file)
    i.thumbnail(output_size)
    i.save(filepath)

    return filename


@app.route('/')
def index():
    conn = get_db()
    c = conn.cursor()
    c.execute('SELECT * FROM posts ORDER BY created_at DESC LIMIT 50')
    posts = c.fetchall()
    conn.close()
    return render_template('index.html', posts=posts)


@app.route('/register', methods=['GET', 'POST'])
def register():
    if request.method == 'POST':
        username = request.form['username']
        email = request.form['email']
        password = request.form['password']

        conn = get_db()
        c = conn.cursor()

        c.execute('SELECT id FROM users WHERE username = ?', (username,))
        if c.fetchone():
            flash('Username already exists')
            return redirect(url_for('register'))

        c.execute('SELECT id FROM users WHERE email = ?', (email,))
        if c.fetchone():
            flash('Email already exists')
            return redirect(url_for('register'))

        hashed_password = generate_password_hash(password)
        c.execute('INSERT INTO users (username, email, password_hash) VALUES (?, ?, ?)',
                  (username, email, hashed_password))
        conn.commit()

        user_id = c.lastrowid
        conn.close()

        session['user_id'] = user_id
        session['username'] = username
        flash('Registration successful')
        return redirect(url_for('index'))

    return render_template('register.html')


@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']

        conn = get_db()
        c = conn.cursor()
        c.execute('SELECT * FROM users WHERE username = ?', (username,))
        user = c.fetchone()
        conn.close()

        if user and check_password_hash(user['password_hash'], password):
            session['user_id'] = user['id']
            session['username'] = user['username']
            flash('Login successful')
            return redirect(url_for('index'))

        flash('Invalid username or password')

    return render_template('login.html')


@app.route('/logout')
def logout():
    session.clear()
    flash('You have been logged out')
    return redirect(url_for('index'))


if __name__ == '__main__':
    init_db()
    if not os.path.exists(app.config['UPLOAD_FOLDER']):
        os.makedirs(app.config['UPLOAD_FOLDER'])
    app.run(debug=True)