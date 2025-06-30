from flask import Blueprint, render_template, request, redirect, url_for, flash
from .models import User
from . import db
from flask_login import login_user, logout_user, login_required, current_user
from werkzeug.security import generate_password_hash, check_password_hash

auth = Blueprint('auth', __name__)

@auth.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        email = request.form.get('email')
        password = request.form.get('password')
        user = User.query.filter_by(email=email).first()
        if user and check_password_hash(user.password, password):
            login_user(user, remember=True)
            if user.is_admin:
                return redirect(url_for('views.admin_dashboard'))
            else:
                return redirect(url_for('views.employee_dashboard'))
        else:
            flash('Incorrect email or password', category='error')
    return render_template('login.html')

@auth.route('/admin-login', methods=['GET', 'POST'])
def admin_login():
    if request.method == 'POST':
        email = request.form.get('email')
        password = request.form.get('password')
        user = User.query.filter_by(email=email).first()
        if user and user.is_admin and check_password_hash(user.password, password):
            login_user(user)
            return redirect(url_for('views.admin_dashboard'))
        else:
            flash('Invalid admin credentials', 'danger')
    return render_template('admin_login.html')

@auth.route('/create-admin')
def create_admin():
    from werkzeug.security import generate_password_hash
    existing = User.query.filter_by(email='admin@gmail.com').first()
    if not existing:
        admin = User(
            name='Admin',
            email='admin@gmail.com',
            password=generate_password_hash('admin123', method='pbkdf2:sha256'),
            is_admin=True
        )
        db.session.add(admin)
        db.session.commit()
        return "✅ Admin created."
    return "Admin already exists."

@auth.route('/logout')
@login_required
def logout():
    logout_user()
    return redirect(url_for('auth.login'))