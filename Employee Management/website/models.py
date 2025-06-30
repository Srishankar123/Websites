from . import db
from flask_login import UserMixin
from datetime import datetime

class User(db.Model, UserMixin):
    id = db.Column(db.Integer, primary_key=True)
    email = db.Column(db.String(150), unique=True)
    name = db.Column(db.String(150))
    password = db.Column(db.String(150))
    is_admin = db.Column(db.Boolean, default=False)
    complaints = db.relationship('Complaint', backref='assigned_to')

class Complaint(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    customer_name = db.Column(db.String(150))
    description = db.Column(db.Text)
    status = db.Column(db.String(50), default="Pending")  # Pending, Closed, Escalated
    assigned_to_id = db.Column(db.Integer, db.ForeignKey('user.id'))   
    employee = db.relationship('User', backref='complaints_assigned')
    escalate_remarks = db.Column(db.Text, nullable=True)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    
