from flask import Blueprint, render_template, request, redirect, url_for, flash
from flask_login import login_required, current_user
from werkzeug.security import generate_password_hash
from .models import Complaint, User
from . import db

views = Blueprint('views', __name__)

# ------------------- ADMIN DASHBOARD -------------------
@views.route('/admin/dashboard')
@login_required
def admin_dashboard():
    if not current_user.is_admin:
        return redirect(url_for('views.employee_dashboard'))
    
    employees = User.query.filter_by(is_admin=False).all()
    complaints = Complaint.query.all()
    return render_template('admin_dashboard.html', user=current_user, complaints=complaints, employees=employees)

# ------------------- EMPLOYEE DASHBOARD -------------------
@views.route('/employee/dashboard')
@login_required
def employee_dashboard():
    if current_user.is_admin:
        return redirect(url_for('views.admin_dashboard'))

    complaints = Complaint.query.filter_by(assigned_to_id=current_user.id).all()
    return render_template('employee_dashboard.html', user=current_user, complaints=complaints)

# ------------------- CREATE EMPLOYEE -------------------
@views.route('/create-employee', methods=['GET', 'POST'])
@login_required
def create_employee():
    if not current_user.is_admin:
        return redirect(url_for('views.employee_dashboard'))

    if request.method == 'POST':
        name = request.form.get('name')
        email = request.form.get('email')
        password = request.form.get('password')

        existing_user = User.query.filter_by(email=email).first()
        if existing_user:
            flash('❌ Email already exists. Please use a different one.', 'danger')
            return redirect(url_for('views.create_employee'))

        hashed_password = generate_password_hash(password, method='pbkdf2:sha256')
        new_user = User(name=name, email=email, password=hashed_password, is_admin=False)
        db.session.add(new_user)
        db.session.commit()

        flash('✅ Employee created successfully.', 'success')
        return redirect(url_for('views.admin_dashboard'))

    return render_template('create_employee.html')

# ------------------- REGISTER COMPLAINT -------------------
@views.route('/register-complaint', methods=['GET', 'POST'])
@login_required
def register_complaint():
    if not current_user.is_admin:
        return redirect(url_for('views.employee_dashboard'))

    if request.method == 'POST':
        customer_name = request.form.get('customer_name')
        description = request.form.get('description')
        assigned_to = request.form.get('assigned_to')

        assigned_to_id = int(assigned_to) if assigned_to else None

        new_complaint = Complaint(
            customer_name=customer_name,
            description=description,
            assigned_to_id=assigned_to_id
        )
        db.session.add(new_complaint)
        db.session.commit()

        flash("✅ Complaint registered successfully.", "success")
        return redirect(url_for('views.admin_dashboard'))

    employees = User.query.filter_by(is_admin=False).all()
    return render_template('register_complaint.html', employees=employees)

# ------------------- UPDATE COMPLAINT STATUS -------------------
@views.route('/update-complaint/<int:id>', methods=['POST'])
@login_required
def update_complaint(id):
    complaint = Complaint.query.get_or_404(id)
    action = request.form.get('action')

    if action == 'close':
        complaint.status = 'Closed'
    elif action == 'escalate':
        complaint.status = 'Escalated'
        complaint.escalate_remarks = request.form.get('remarks')

    db.session.commit()
    flash(f"✅ Complaint #{complaint.id} updated.", "info")

    return redirect(url_for('views.employee_dashboard' if not current_user.is_admin else 'views.admin_dashboard'))

# ------------------- EMPLOYEE LIST + SEARCH -------------------
@views.route('/employee_list', methods=['GET', 'POST'])
@login_required
def employee_list():
    if not current_user.is_admin:
        return redirect(url_for('views.employee_dashboard'))

    employees = User.query.filter_by(is_admin=False).all()

    if request.method == 'POST':
        employee_name = request.form.get('emp_name', '').strip()
        if employee_name:
            employees = User.query.filter(
                User.is_admin == False,
                User.name.ilike(f"%{employee_name}%")
            ).all()
        else:
            flash("⚠️ Please enter a name to search.", "warning")

    return render_template("employee_list.html", employees=employees)

# ------------------- HOME REDIRECT -------------------
@views.route('/')
def home():
    return redirect(url_for('auth.login'))
