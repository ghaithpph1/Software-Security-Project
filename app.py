from flask import Flask, render_template, request, redirect, url_for, session, flash
from flask_bcrypt import Bcrypt
from flask_sqlalchemy import SQLAlchemy
from cryptography.fernet import Fernet
import os

app = Flask(__name__)
app.secret_key = os.urandom(24)
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///database.db'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False

db = SQLAlchemy(app)
bcrypt = Bcrypt(app)

ENCRYPTION_KEY = b'ZmDfcTF7_60GrrY167zsiPd67pEvs0aJ_rW1RCDkFMM='
cipher = Fernet(ENCRYPTION_KEY)


class User(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(80), unique=True, nullable=False)
    password_hash = db.Column(db.String(256), nullable=False)
    role = db.Column(db.String(20), default='user')
    phone_encrypted = db.Column(db.Text, nullable=True)


@app.route('/')
def index():
    if 'user_id' in session:
        return redirect(url_for('dashboard'))
    return redirect(url_for('login'))


@app.route('/register', methods=['GET', 'POST'])
def register():
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']
        phone = request.form['phone']

        existing_user = User.query.filter_by(username=username).first()
        if existing_user:
            flash('Username already exists. Please choose another.', 'error')
            return redirect(url_for('register'))

        hashed_password = bcrypt.generate_password_hash(password).decode('utf-8')
        encrypted_phone = cipher.encrypt(phone.encode()).decode()

        new_user = User(
            username=username,
            password_hash=hashed_password,
            role='user',
            phone_encrypted=encrypted_phone
        )
        db.session.add(new_user)
        db.session.commit()

        flash('Account created successfully. Please log in.', 'success')
        return redirect(url_for('login'))

    return render_template('register.html')


@app.route('/login', methods=['GET', 'POST'])
def login():
    error = None
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']
        user = User.query.filter_by(username=username).first()
        if user and bcrypt.check_password_hash(user.password_hash, password):
            session['user_id'] = user.id
            session['role'] = user.role
            session['username'] = user.username
            return redirect(url_for('dashboard'))
        else:
            error = 'Invalid username or password.'
    return render_template('login.html', error=error)


@app.route('/dashboard')
def dashboard():
    if 'user_id' not in session:
        return redirect(url_for('login'))
    user = User.query.get(session['user_id'])
    phone = 'Not set'
    if user.phone_encrypted:
        phone = cipher.decrypt(user.phone_encrypted.encode()).decode()
    return render_template('user_dashboard.html', user=user, phone=phone)


@app.route('/admin')
def admin():
    if 'user_id' not in session:
        return redirect(url_for('login'))
    if session.get('role') != 'admin':
        return render_template('access_denied.html'), 403
    users = User.query.all()
    return render_template('admin_dashboard.html', users=users)


@app.route('/logout')
def logout():
    session.clear()
    return redirect(url_for('login'))


def setup_database():
    with app.app_context():
        db.create_all()
        if not User.query.filter_by(username='admin').first():
            admin_phone = cipher.encrypt(b'+966501234567').decode()
            admin_user = User(
                username='admin',
                password_hash=bcrypt.generate_password_hash('admin123').decode(),
                role='admin',
                phone_encrypted=admin_phone
            )
            db.session.add(admin_user)
            db.session.commit()


setup_database()

if __name__ == '__main__':
    app.run(debug=True)