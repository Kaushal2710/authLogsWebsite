
# app.py
from flask import Flask, render_template, redirect, url_for, request, flash
from flask_sqlalchemy import SQLAlchemy
from flask_login import LoginManager, UserMixin, login_user, logout_user, login_required, current_user
from werkzeug.security import generate_password_hash, check_password_hash
from datetime import datetime
import os
import json


from config import Config
from utils.logger import AuthLogger

app = Flask(__name__)
app.config.from_object(Config)

PORT = int(os.getenv("PORT", 10000))  # Default to 10000 if PORT is not set
app.run(host="0.0.0.0", port=PORT)

# Initialize database
db = SQLAlchemy(app)

# Initialize login manager
login_manager = LoginManager()
login_manager.init_app(app)
login_manager.login_view = 'login'

# Initialize logger
auth_logger = AuthLogger(app.config['LOG_FILE'])

# User model
class User(UserMixin, db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(80), unique=True, nullable=False)
    email = db.Column(db.String(120), unique=True, nullable=False)
    password_hash = db.Column(db.String(128))
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    last_login = db.Column(db.DateTime, nullable=True)
    
    def set_password(self, password):
        self.password_hash = generate_password_hash(password)
        
    def check_password(self, password):
        return check_password_hash(self.password_hash, password)
    
    def __repr__(self):
        return f'<User {self.username}>'

@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))

# Create database tables
with app.app_context():
    db.create_all()

@app.route('/')
def index():
    if current_user.is_authenticated:
        return redirect(url_for('dashboard'))
    return redirect(url_for('login'))

@app.route('/register', methods=['GET', 'POST'])
def register():
    if current_user.is_authenticated:
        return redirect(url_for('dashboard'))
    
    if request.method == 'POST':
        username = request.form.get('username')
        email = request.form.get('email')
        password = request.form.get('password')
        confirm_password = request.form.get('confirm_password')
        
        # Log the registration attempt
        auth_logger.log_auth_event(
            event_type='registration_attempt',
            username=username,
            success=False,
            details={'email': email}
        )
        
        # Validate form data
        if not username or not email or not password or not confirm_password:
            flash('All fields are required', 'danger')
            return render_template('register.html')
            
        if password != confirm_password:
            flash('Passwords do not match', 'danger')
            return render_template('register.html')
            
        # Check if username or email already exists
        existing_user = User.query.filter_by(username=username).first()
        if existing_user:
            flash('Username already exists', 'danger')
            return render_template('register.html')
            
        existing_email = User.query.filter_by(email=email).first()
        if existing_email:
            flash('Email already registered', 'danger')
            return render_template('register.html')
        
        # Create new user
        new_user = User(username=username, email=email)
        new_user.set_password(password)
        
        try:
            db.session.add(new_user)
            db.session.commit()
            
            # Log successful registration
            auth_logger.log_auth_event(
                event_type='registration_success',
                username=username,
                success=True,
                details={'email': email, 'user_id': new_user.id}
            )
            
            flash('Registration successful! You can now log in.', 'success')
            return redirect(url_for('login'))
            
        except Exception as e:
            db.session.rollback()
            # Log registration error
            auth_logger.log_auth_event(
                event_type='registration_error',
                username=username,
                success=False,
                details={'error': str(e), 'email': email}
            )
            flash('An error occurred during registration', 'danger')
            
    return render_template('register.html')

@app.route('/login', methods=['GET', 'POST'])
def login():
    if current_user.is_authenticated:
        return redirect(url_for('dashboard'))
    
    if request.method == 'POST':
        username = request.form.get('username')
        password = request.form.get('password')
        remember = True if request.form.get('remember') else False
        
        # Log login attempt
        auth_logger.log_auth_event(
            event_type='login_attempt',
            username=username,
            success=False
        )
        
        # Validate form data
        if not username or not password:
            flash('Username and password are required', 'danger')
            return render_template('login.html')
        
        # Check if user exists
        user = User.query.filter_by(username=username).first()
        
        if not user or not user.check_password(password):
            # Log failed login
            auth_logger.log_auth_event(
                event_type='login_failed',
                username=username,
                success=False,
                details={'reason': 'Invalid credentials'}
            )
            flash('Invalid username or password', 'danger')
            return render_template('login.html')
        
        # Update last login time
        user.last_login = datetime.utcnow()
        db.session.commit()
        
        # Log in user
        login_user(user, remember=remember)
        
        # Log successful login
        auth_logger.log_auth_event(
            event_type='login_success',
            username=username,
            success=True,
            details={'user_id': user.id, 'remember_me': remember}
        )
        
        # Redirect to next page or dashboard
        next_page = request.args.get('next')
        if next_page:
            return redirect(next_page)
        return redirect(url_for('dashboard'))
    
    return render_template('login.html')

@app.route('/logout')
@login_required
def logout():
    username = current_user.username
    user_id = current_user.id
    
    logout_user()
    
    # Log logout
    auth_logger.log_auth_event(
        event_type='logout',
        username=username,
        success=True,
        details={'user_id': user_id}
    )
    
    flash('You have been logged out', 'info')
    return redirect(url_for('login'))

@app.route('/dashboard')
@login_required
def dashboard():
    return render_template('dashboard.html')

if __name__ == '__main__':
    app.run(debug=True)