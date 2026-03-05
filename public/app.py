from flask import Flask, render_template, request, redirect, url_for, flash, session, jsonify, abort, send_file
from werkzeug.security import generate_password_hash, check_password_hash
from flask_sqlalchemy import SQLAlchemy
from sqlalchemy import text, or_, and_
from datetime import timedelta, datetime
import secrets
from werkzeug.utils import secure_filename
import re
import os
import csv
import io
import subprocess
import shlex
import logging
from logging.handlers import RotatingFileHandler
from functools import wraps
import hashlib
import hmac
import uuid

app = Flask(__name__)

# ==================== SECURITY CONFIGURATION ====================

# Use environment variables for secrets (NEVER hardcode in production)
app.secret_key = os.environ.get('SECRET_KEY', 'dev-secret-key-swiftsupport-2024')
if os.environ.get('FLASK_ENV') == 'production' and not os.environ.get('SECRET_KEY'):
    raise RuntimeError("SECRET_KEY environment variable not set in production!")

# Session security
app.config['SESSION_COOKIE_SECURE'] = False  # Set to True only with HTTPS
app.config['SESSION_COOKIE_HTTPONLY'] = True
app.config['SESSION_COOKIE_SAMESITE'] = 'Lax'
app.config['PERMANENT_SESSION_LIFETIME'] = timedelta(minutes=30)
app.config['SESSION_REFRESH_EACH_REQUEST'] = True

# Database configuration
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///swiftsupport.db'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
app.config['SQLALCHEMY_ENGINE_OPTIONS'] = {
    'pool_pre_ping': True,
    'pool_recycle': 300,
}

# File upload security
UPLOAD_FOLDER = 'uploads'
KNOWLEDGE_BASE_FOLDER = 'knowledge_base_files'
ALLOWED_EXTENSIONS = {'png', 'jpg', 'jpeg', 'gif', 'pdf', 'txt'}
MAX_FILE_SIZE = 5 * 1024 * 1024  # 5MB
app.config['UPLOAD_FOLDER'] = UPLOAD_FOLDER
app.config['KNOWLEDGE_BASE_FOLDER'] = KNOWLEDGE_BASE_FOLDER
app.config['MAX_CONTENT_LENGTH'] = MAX_FILE_SIZE

# Ensure folders exist with proper permissions
os.makedirs(UPLOAD_FOLDER, exist_ok=True)
os.makedirs(KNOWLEDGE_BASE_FOLDER, exist_ok=True)
os.chmod(UPLOAD_FOLDER, 0o750)
os.chmod(KNOWLEDGE_BASE_FOLDER, 0o750)

# Security headers
@app.after_request
def add_security_headers(response):
    """Add security headers to all responses"""
    response.headers['X-Content-Type-Options'] = 'nosniff'
    response.headers['X-Frame-Options'] = 'SAMEORIGIN'
    response.headers['X-XSS-Protection'] = '1; mode=block'
    return response

# Logging setup
if not app.debug:
    handler = RotatingFileHandler('security.log', maxBytes=10000, backupCount=3)
    handler.setLevel(logging.WARNING)
    app.logger.addHandler(handler)

db = SQLAlchemy(app)

if not os.path.exists('swiftsupport.db'):
    print("🔵 No database found, will create one")

# ==================== DECORATORS ====================

def login_required(f):
    """Require authentication decorator"""
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if 'user_id' not in session:
            flash('Please log in to access this page.', 'warning')
            return redirect(url_for('index'))
        return f(*args, **kwargs)
    return decorated_function

def admin_required(f):
    """Require admin privileges decorator"""
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if 'user_id' not in session:
            flash('Please log in to access this page.', 'warning')
            return redirect(url_for('index'))
        
        user = db.session.get(User, session['user_id'])
        if not user or not user.is_admin:
            app.logger.warning(f"Unauthorized admin access attempt by user {session.get('user_id')}")
            abort(403)
        
        return f(*args, **kwargs)
    return decorated_function

# ==================== DATABASE MODELS ====================

class User(db.Model):
    __tablename__ = 'users'
    
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(80), unique=True, nullable=False)
    email = db.Column(db.String(120), unique=True, nullable=False)
    password_hash = db.Column(db.String(256), nullable=False)
    
    # Personal information (matching original)
    full_name = db.Column(db.String(100), nullable=False)
    company = db.Column(db.String(100))
    phone = db.Column(db.String(20))
    
    # Original sensitive fields (kept for demo)
    ssn = db.Column(db.String(11))
    credit_card_number = db.Column(db.String(16))
    credit_card_expiry = db.Column(db.String(5))
    credit_card_cvv = db.Column(db.String(4))
    
    # Address
    address = db.Column(db.String(200))
    city = db.Column(db.String(50))
    state = db.Column(db.String(20))
    zip_code = db.Column(db.String(10))
    country = db.Column(db.String(50))
    
    # Account settings
    account_type = db.Column(db.String(20), default='individual')
    is_verified = db.Column(db.Boolean, default=False)
    is_admin = db.Column(db.Boolean, default=False)
    created_at = db.Column(db.DateTime, server_default=db.func.now())
    
    # Security fields
    last_login_at = db.Column(db.DateTime)
    last_login_ip = db.Column(db.String(45))
    failed_login_attempts = db.Column(db.Integer, default=0)
    locked_until = db.Column(db.DateTime)
    password_changed_at = db.Column(db.DateTime, server_default=db.func.now())
    password_reset_token = db.Column(db.String(100), unique=True)
    password_reset_expires = db.Column(db.DateTime)
    
    def __repr__(self):
        return f'<User {self.username}>'
    
    def set_password(self, password):
        """Hash password"""
        self.password_hash = generate_password_hash(password)
        self.password_changed_at = datetime.utcnow()
    
    def check_password(self, password):
        """Verify password"""
        # Check if account is locked
        if self.locked_until and self.locked_until > datetime.utcnow():
            return False
        
        # Verify password
        valid = check_password_hash(self.password_hash, password)
        
        if not valid:
            self.failed_login_attempts += 1
            if self.failed_login_attempts >= 5:
                self.locked_until = datetime.utcnow() + timedelta(minutes=15)
            db.session.commit()
        else:
            self.failed_login_attempts = 0
            self.locked_until = None
            db.session.commit()
        
        return valid
    
    def mask_ssn(self):
        """Return masked SSN for display"""
        if self.ssn and len(self.ssn) >= 4:
            return f"XXX-XX-{self.ssn[-4:]}"
        return None
    
    def mask_credit_card(self):
        """Return masked credit card for display"""
        if self.credit_card_number and len(self.credit_card_number) >= 4:
            return f"XXXX-XXXX-XXXX-{self.credit_card_number[-4:]}"
        return None
    
    def to_safe_dict(self):
        """Safe dictionary representation"""
        return {
            'id': self.id,
            'username': self.username,
            'email': self.email,
            'full_name': self.full_name,
            'company': self.company,
            'phone': self.phone,
            'address': self.address,
            'city': self.city,
            'state': self.state,
            'zip_code': self.zip_code,
            'country': self.country,
            'account_type': self.account_type,
            'is_verified': self.is_verified,
            'is_admin': self.is_admin,
            'created_at': self.created_at.isoformat() if self.created_at else None,
            'last_login': self.last_login_at.isoformat() if self.last_login_at else None,
            'ssn_masked': self.mask_ssn(),
            'credit_card_masked': self.mask_credit_card(),
        }

class KnowledgeBaseArticle(db.Model):
    """Secure knowledge base article storage"""
    __tablename__ = 'knowledge_base_articles'
    
    id = db.Column(db.Integer, primary_key=True)
    title = db.Column(db.String(200), nullable=False)
    slug = db.Column(db.String(200), unique=True, nullable=False)
    content = db.Column(db.Text, nullable=False)
    category = db.Column(db.String(50), default='General')
    tags = db.Column(db.String(200))
    views = db.Column(db.Integer, default=0)
    is_published = db.Column(db.Boolean, default=True)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    updated_at = db.Column(db.DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)
    created_by = db.Column(db.Integer, db.ForeignKey('users.id'))
    
    # File attachments
    attachment_filename = db.Column(db.String(200))
    original_filename = db.Column(db.String(200))
    
    def __repr__(self):
        return f'<KnowledgeBaseArticle {self.title}>'
    
    def increment_views(self):
        self.views += 1
        db.session.commit()

class Ticket(db.Model):
    __tablename__ = 'tickets'
    
    id = db.Column(db.Integer, primary_key=True)
    ticket_number = db.Column(db.String(20), unique=True, nullable=False)
    customer_id = db.Column(db.Integer, db.ForeignKey('users.id'), nullable=False)
    subject = db.Column(db.String(200), nullable=False)
    description = db.Column(db.Text, nullable=False)
    category = db.Column(db.String(50), default='General')
    priority = db.Column(db.String(20), default='Medium')
    status = db.Column(db.String(20), default='Open')
    impact = db.Column(db.String(50))
    related_ticket = db.Column(db.String(20))
    
    # Timestamps
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    updated_at = db.Column(db.DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)
    resolved_at = db.Column(db.DateTime)
    
    # Assignment
    assigned_to = db.Column(db.Integer, db.ForeignKey('users.id'), nullable=True)
    
    # Metadata
    attachment_path = db.Column(db.String(200))
    internal_notes = db.Column(db.Text)
    
    # SLA tracking
    first_response_at = db.Column(db.DateTime)
    response_time_minutes = db.Column(db.Integer)
    
    # Relationships
    customer = db.relationship('User', foreign_keys=[customer_id], backref='tickets')
    agent = db.relationship('User', foreign_keys=[assigned_to], backref='assigned_tickets')
    
    def __repr__(self):
        return f'<Ticket {self.ticket_number}>'
    
    def can_access(self, user):
        """Check if user can access this ticket"""
        if user.is_admin:
            return True
        return self.customer_id == user.id

class TicketMessage(db.Model):
    __tablename__ = 'ticket_messages'
    
    id = db.Column(db.Integer, primary_key=True)
    ticket_id = db.Column(db.Integer, db.ForeignKey('tickets.id'), nullable=False)
    author_id = db.Column(db.Integer, db.ForeignKey('users.id'), nullable=False)
    message = db.Column(db.Text, nullable=False)
    is_internal = db.Column(db.Boolean, default=False)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    
    # Relationships
    author = db.relationship('User', foreign_keys=[author_id])
    ticket = db.relationship('Ticket', backref='messages', foreign_keys=[ticket_id])

class Notification(db.Model):
    __tablename__ = 'notifications'
    
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('users.id'), nullable=False)
    title = db.Column(db.String(200), nullable=False)
    message = db.Column(db.Text, nullable=False)
    type = db.Column(db.String(50), default='info')
    is_read = db.Column(db.Boolean, default=False)
    link = db.Column(db.String(200))
    created_at = db.Column(db.DateTime, default=datetime.utcnow)

class Announcement(db.Model):
    __tablename__ = 'announcements'
    
    id = db.Column(db.Integer, primary_key=True)
    title = db.Column(db.String(200), nullable=False)
    content = db.Column(db.Text, nullable=False)
    priority = db.Column(db.String(20), default='normal')
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    expires_at = db.Column(db.DateTime)
    is_active = db.Column(db.Boolean, default=True)

class Maintenance(db.Model):
    __tablename__ = 'maintenance'
    
    id = db.Column(db.Integer, primary_key=True)
    title = db.Column(db.String(200), nullable=False)
    description = db.Column(db.Text, nullable=False)
    scheduled_start = db.Column(db.DateTime, nullable=False)
    scheduled_end = db.Column(db.DateTime, nullable=False)
    status = db.Column(db.String(20), default='scheduled')
    created_at = db.Column(db.DateTime, default=datetime.utcnow)

class PaymentMethod(db.Model):
    __tablename__ = 'payment_methods'
    
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('users.id'), nullable=False)
    card_type = db.Column(db.String(20))
    card_number = db.Column(db.String(16))
    cardholder_name = db.Column(db.String(100))
    expiry_month = db.Column(db.Integer)
    expiry_year = db.Column(db.Integer)
    is_default = db.Column(db.Boolean, default=False)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    
    user = db.relationship('User', backref='payment_methods')
    
    @property
    def masked_number(self):
        if self.card_number and len(self.card_number) >= 4:
            return f"**** **** **** {self.card_number[-4:]}"
        return "**** **** **** ****"
    
    @property
    def expiry_display(self):
        return f"{self.expiry_month:02d}/{self.expiry_year}"

class Invoice(db.Model):
    __tablename__ = 'invoices'
    
    id = db.Column(db.Integer, primary_key=True)
    invoice_number = db.Column(db.String(20), unique=True, nullable=False)
    user_id = db.Column(db.Integer, db.ForeignKey('users.id'), nullable=False)
    amount = db.Column(db.Float, nullable=False)
    tax = db.Column(db.Float, default=0.0)
    total = db.Column(db.Float, nullable=False)
    issue_date = db.Column(db.DateTime, default=datetime.utcnow)
    due_date = db.Column(db.DateTime)
    paid_date = db.Column(db.DateTime)
    status = db.Column(db.String(20), default='pending')
    description = db.Column(db.String(200))
    
    user = db.relationship('User', backref='invoices')
    
    @property
    def is_paid(self):
        return self.status == 'paid'

class AuditLog(db.Model):
    __tablename__ = 'audit_logs'
    
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('users.id'), nullable=True)
    action = db.Column(db.String(100), nullable=False)
    ip_address = db.Column(db.String(45))
    user_agent = db.Column(db.String(200))
    details = db.Column(db.Text)
    timestamp = db.Column(db.DateTime, default=datetime.utcnow)

# ==================== INITIALIZATION FUNCTION ====================

def init_db():
    """Initialize database with all original sample data"""
    with app.app_context():
        # Create all tables
        db.create_all()
        
        # Check if we already have users
        if not User.query.first():
            print("📊 Creating sample users...")
            
            # Create users 
            users = [
                User(
                    username='john_doe',
                    email='john@example.com',
                    full_name='John Doe',
                    company='Acme Corporation',
                    phone='(555) 123-4567',
                    ssn='123-45-6789',
                    credit_card_number='4111111111111111',
                    credit_card_expiry='12/25',
                    credit_card_cvv='123',
                    address='123 Main St',
                    city='San Francisco',
                    state='CA',
                    zip_code='94105',
                    country='USA',
                    account_type='business',
                    is_verified=True
                ),
                User(
                    username='jane_smith',
                    email='jane@example.com',
                    full_name='Jane Smith',
                    company='Globex Corporation',
                    phone='(555) 987-6543',
                    ssn='987-65-4321',
                    credit_card_number='5500000000000004',
                    credit_card_expiry='08/24',
                    credit_card_cvv='456',
                    address='456 Oak Ave',
                    city='Los Angeles',
                    state='CA',
                    zip_code='90001',
                    country='USA',
                    account_type='business',
                    is_verified=True
                ),
                User(
                    username='bob_wilson',
                    email='bob@example.com',
                    full_name='Bob Wilson',
                    ssn='456-78-9012',
                    credit_card_number='3400000000000009',
                    credit_card_expiry='03/26',
                    credit_card_cvv='789',
                    address='789 Pine St',
                    city='New York',
                    state='NY',
                    zip_code='10001',
                    country='USA',
                    account_type='individual',
                    is_verified=True
                ),
                User(
                    username='admin',
                    email='admin@swiftsupport.com',
                    full_name='System Administrator',
                    ssn='000-00-0000',
                    is_admin=True,
                    is_verified=True
                )
            ]
            
            # Set passwords
            users[0].set_password('password123')
            users[1].set_password('password456')
            users[2].set_password('password789')
            users[3].set_password('admin123')
            
            for user in users:
                db.session.add(user)
            db.session.commit()
            
            print("✅ Sample users created!")
            print("   - Regular: john_doe / password123")
            print("   - Regular: jane_smith / password456")
            print("   - Regular: bob_wilson / password789")
            print("   - Admin: admin / admin123")
            
            # Get user IDs for relationships
            john = User.query.filter_by(username='john_doe').first()
            admin = User.query.filter_by(username='admin').first()
            
            # Create sample tickets
            print("📊 Creating sample tickets...")
            tickets = [
                Ticket(
                    ticket_number='SUP-2024-001',
                    customer_id=john.id,
                    subject='Cannot access email account',
                    description='I keep getting "Invalid password" error when trying to access my email.',
                    category='Technical',
                    priority='High',
                    status='Open',
                    created_at=datetime.utcnow() - timedelta(days=2),
                    assigned_to=admin.id
                ),
                Ticket(
                    ticket_number='SUP-2024-002',
                    customer_id=john.id,
                    subject='Billing discrepancy on last invoice',
                    description='I was charged twice for last month\'s service.',
                    category='Billing',
                    priority='Medium',
                    status='In Progress',
                    created_at=datetime.utcnow() - timedelta(days=5),
                    assigned_to=admin.id,
                    internal_notes='Customer called about duplicate charge. Refund processed.'
                ),
                Ticket(
                    ticket_number='SUP-2024-003',
                    customer_id=john.id,
                    subject='Need to update company information',
                    description='Our company address has changed. Need to update in the system.',
                    category='Account',
                    priority='Low',
                    status='Open',
                    created_at=datetime.utcnow() - timedelta(days=1)
                ),
                Ticket(
                    ticket_number='SUP-2024-004',
                    customer_id=john.id,
                    subject='Feature request: Bulk export',
                    description='Would like ability to export all tickets to CSV.',
                    category='Feature Request',
                    priority='Low',
                    status='Closed',
                    created_at=datetime.utcnow() - timedelta(days=30),
                    resolved_at=datetime.utcnow() - timedelta(days=28)
                ),
                Ticket(
                    ticket_number='SUP-2024-005',
                    customer_id=john.id,
                    subject='API integration help',
                    description='Need assistance with API authentication.',
                    category='Technical',
                    priority='Medium',
                    status='Resolved',
                    created_at=datetime.utcnow() - timedelta(days=15),
                    resolved_at=datetime.utcnow() - timedelta(days=14)
                )
            ]
            
            for ticket in tickets:
                db.session.add(ticket)
            db.session.commit()
            
            # Create ticket messages
            print("📊 Creating ticket messages...")
            ticket1 = Ticket.query.filter_by(ticket_number='SUP-2024-001').first()
            
            messages = [
                TicketMessage(
                    ticket_id=ticket1.id,
                    author_id=john.id,
                    message='I have tried resetting my password but still cannot login.',
                    created_at=datetime.utcnow() - timedelta(days=2)
                ),
                TicketMessage(
                    ticket_id=ticket1.id,
                    author_id=admin.id,
                    message='I can see the issue from our end. Your account is locked due to multiple failed attempts. I have unlocked it.',
                    created_at=datetime.utcnow() - timedelta(days=1, hours=12)
                ),
                TicketMessage(
                    ticket_id=ticket1.id,
                    author_id=admin.id,
                    message="Please try logging in now. (Note: Customer's last 4 SSN: 6789)",
                    is_internal=True,
                    created_at=datetime.utcnow() - timedelta(days=1, hours=11)
                ),
                TicketMessage(
                    ticket_id=ticket1.id,
                    author_id=john.id,
                    message='It works now! Thank you for the quick assistance.',
                    created_at=datetime.utcnow() - timedelta(days=1)
                )
            ]
            
            for msg in messages:
                db.session.add(msg)
            db.session.commit()
            
            # Create announcements
            print("📊 Creating announcements...")
            announcements = [
                Announcement(
                    title='📢 New Feature: Ticket Export',
                    content='You can now export your tickets to CSV format from the tickets page.',
                    priority='normal',
                    created_at=datetime.utcnow() - timedelta(days=2)
                ),
                Announcement(
                    title='🎉 Holiday Support Hours',
                    content='Our support hours will be reduced during the upcoming holiday weekend. Please plan accordingly.',
                    priority='high',
                    created_at=datetime.utcnow() - timedelta(days=1)
                ),
                Announcement(
                    title='🔧 System Maintenance',
                    content='Scheduled maintenance this Sunday from 2 AM to 4 AM EST. The portal will be briefly unavailable.',
                    priority='high',
                    created_at=datetime.utcnow() - timedelta(hours=12)
                )
            ]
            
            for ann in announcements:
                db.session.add(ann)
            db.session.commit()
            
            # Create maintenance windows
            print("📊 Creating maintenance schedules...")
            maintenances = [
                Maintenance(
                    title='Database Upgrade',
                    description='We will be upgrading our database systems to improve performance.',
                    scheduled_start=datetime.utcnow() + timedelta(days=3),
                    scheduled_end=datetime.utcnow() + timedelta(days=3, hours=2),
                    status='scheduled'
                ),
                Maintenance(
                    title='Security Patch Deployment',
                    description='Critical security patches will be deployed.',
                    scheduled_start=datetime.utcnow() + timedelta(days=7),
                    scheduled_end=datetime.utcnow() + timedelta(days=7, hours=1),
                    status='scheduled'
                )
            ]
            
            for maint in maintenances:
                db.session.add(maint)
            db.session.commit()
            
            # Create notifications
            print("📊 Creating notifications...")
            notifications = [
                Notification(
                    user_id=john.id,
                    title='Ticket Updated',
                    message='Your ticket SUP-2024-001 has been updated by support.',
                    type='info',
                    link='/customer/ticket/SUP-2024-001',
                    created_at=datetime.utcnow() - timedelta(hours=5)
                ),
                Notification(
                    user_id=john.id,
                    title='Maintenance Notice',
                    message='Scheduled maintenance in 3 days.',
                    type='warning',
                    link='/customer/maintenance',
                    created_at=datetime.utcnow() - timedelta(hours=2)
                ),
                Notification(
                    user_id=john.id,
                    title='Billing Receipt',
                    message='Your payment of $49.99 has been processed.',
                    type='success',
                    link='/customer/billing',
                    created_at=datetime.utcnow() - timedelta(days=1)
                )
            ]
            
            for notif in notifications:
                db.session.add(notif)
            db.session.commit()
            
            # Create payment methods
            print("📊 Creating payment methods...")
            payment_methods = [
                PaymentMethod(
                    user_id=john.id,
                    card_type='Visa',
                    card_number='4111111111111111',
                    cardholder_name='John Doe',
                    expiry_month=12,
                    expiry_year=2025,
                    is_default=True
                ),
                PaymentMethod(
                    user_id=john.id,
                    card_type='Mastercard',
                    card_number='5500000000000004',
                    cardholder_name='John Doe',
                    expiry_month=8,
                    expiry_year=2024,
                    is_default=False
                )
            ]
            
            jane = User.query.filter_by(username='jane_smith').first()
            if jane:
                payment_methods.append(
                    PaymentMethod(
                        user_id=jane.id,
                        card_type='Amex',
                        card_number='340000000000009',
                        cardholder_name='Jane Smith',
                        expiry_month=3,
                        expiry_year=2026,
                        is_default=True
                    )
                )
            
            for pm in payment_methods:
                db.session.add(pm)
            db.session.commit()
            
            # Create invoices
            print("📊 Creating invoices...")
            invoices = [
                Invoice(
                    invoice_number='INV-2024-001',
                    user_id=john.id,
                    amount=49.99,
                    tax=4.00,
                    total=53.99,
                    issue_date=datetime.utcnow() - timedelta(days=30),
                    due_date=datetime.utcnow() - timedelta(days=15),
                    paid_date=datetime.utcnow() - timedelta(days=28),
                    status='paid',
                    description='Monthly subscription - January'
                ),
                Invoice(
                    invoice_number='INV-2024-002',
                    user_id=john.id,
                    amount=49.99,
                    tax=4.00,
                    total=53.99,
                    issue_date=datetime.utcnow() - timedelta(days=5),
                    due_date=datetime.utcnow() + timedelta(days=25),
                    paid_date=None,
                    status='pending',
                    description='Monthly subscription - February'
                )
            ]
            
            if jane:
                invoices.append(
                    Invoice(
                        invoice_number='INV-2024-003',
                        user_id=jane.id,
                        amount=99.99,
                        tax=8.00,
                        total=107.99,
                        issue_date=datetime.utcnow() - timedelta(days=15),
                        due_date=datetime.utcnow() + timedelta(days=15),
                        paid_date=datetime.utcnow() - timedelta(days=10),
                        status='paid',
                        description='Business plan - February'
                    )
                )
            
            for inv in invoices:
                db.session.add(inv)
            db.session.commit()
            
            
            print("✅ All sample data created successfully!")
            print("=" * 50)
            
        else:
            print("📊 Database already has data, skipping initialization")

# Initialize database
init_db()

# ==================== HELPER FUNCTIONS ====================

def get_kb_files():
    """Get list of knowledge base files"""
    files = []
    if not os.path.exists(KNOWLEDGE_BASE_FOLDER):
        os.makedirs(KNOWLEDGE_BASE_FOLDER)
        return files
    
    for filename in os.listdir(KNOWLEDGE_BASE_FOLDER):
        file_path = os.path.join(KNOWLEDGE_BASE_FOLDER, filename)
        if os.path.isfile(file_path):
            # Get file info
            stat = os.stat(file_path)
            name_without_ext = os.path.splitext(filename)[0]
            
            files.append({
                'filename': filename,
                'title': name_without_ext.replace('_', ' ').replace('-', ' '),
                'size': stat.st_size,
                'modified': stat.st_mtime,
                'extension': os.path.splitext(filename)[1].lower()
            })
    
    return sorted(files, key=lambda x: x['title'])

def is_safe_path(basedir, path):
    """Check if path is safe"""
    base_path = os.path.realpath(basedir)
    target_path = os.path.realpath(os.path.join(basedir, path))
    return target_path.startswith(base_path)

def generate_ticket_number():
    """Generate a unique ticket number"""
    year = datetime.now().year
    last_ticket = Ticket.query.order_by(Ticket.id.desc()).first()
    if last_ticket:
        last_num = int(last_ticket.ticket_number.split('-')[-1])
        new_num = last_num + 1
    else:
        new_num = 1
    return f"SUP-{year}-{new_num:03d}"

def allowed_file(filename):
    """Check if file extension is allowed"""
    return '.' in filename and filename.rsplit('.', 1)[1].lower() in ALLOWED_EXTENSIONS

def save_uploaded_file(file, folder=UPLOAD_FOLDER):
    """Securely save uploaded file"""
    if not file or not file.filename:
        return None, None
    
    # Check file size
    file.seek(0, os.SEEK_END)
    size = file.tell()
    file.seek(0)
    
    if size > MAX_FILE_SIZE:
        raise ValueError("File too large")
    
    # Check file type
    if not allowed_file(file.filename):
        raise ValueError("File type not allowed")
    
    # Store original filename for reference
    original_filename = file.filename
    
    # Generate safe filename
    safe_name = secure_filename(file.filename)
    unique_id = secrets.token_hex(8)
    timestamp = datetime.now().strftime('%Y%m%d_%H%M%S')
    filename = f"{timestamp}_{unique_id}_{safe_name}"
    
    # Save file
    file_path = os.path.join(folder, filename)
    file.save(file_path)
    
    # Set restrictive permissions
    os.chmod(file_path, 0o640)
    
    return filename, original_filename

def get_safe_file_path(filename, folder=UPLOAD_FOLDER):
    """Get safe file path with traversal protection"""
    if not filename:
        return None
    
    # Prevent path traversal
    if '..' in filename or filename.startswith('/') or '\\' in filename:
        return None
    
    # Construct path
    file_path = os.path.join(folder, filename)
    
    # Canonicalize and verify
    real_path = os.path.realpath(file_path)
    folder_path = os.path.realpath(folder)
    
    if not real_path.startswith(folder_path):
        return None
    
    return real_path

def log_audit(action, details=None):
    """Log security-relevant events"""
    if 'user_id' in session:
        log = AuditLog(
            user_id=session['user_id'],
            action=action,
            ip_address=request.remote_addr,
            user_agent=request.user_agent.string[:200] if request.user_agent else None,
            details=details
        )
        db.session.add(log)
        db.session.commit()



# ==================== PUBLIC ROUTES ====================

@app.route('/')
def index():
    """Home page with login form"""
    if 'user_id' in session:
        user = db.session.get(User, session['user_id'])
        if user and user.is_admin:
            return redirect(url_for('admin_dashboard'))
        return redirect(url_for('customer_dashboard'))
    return render_template('index.html')

@app.route('/login', methods=['POST'])
def login():
    """Process login - SECURE version with ORM"""
    username = request.form.get('username', '').strip()
    password = request.form.get('password', '')
    remember = request.form.get('remember', False)
    
    if not username or not password:
        flash('Username and password are required.', 'error')
        return redirect(url_for('index'))
    
    # SECURE: Using ORM, not raw SQL
    user = User.query.filter(
        (User.username == username) | (User.email == username)
    ).first()
    
    if user and user.check_password(password):
        # Check if account is locked
        if user.locked_until and user.locked_until > datetime.utcnow():
            flash('Account is temporarily locked. Please try again later.', 'error')
            return redirect(url_for('index'))
        
        # Set session
        session.permanent = True if remember else False
        session['user_id'] = user.id
        session['username'] = user.username
        session['is_admin'] = user.is_admin
        
        # Update user login info
        user.last_login_at = datetime.utcnow()
        user.last_login_ip = request.remote_addr
        user.failed_login_attempts = 0
        user.locked_until = None
        db.session.commit()
        
        log_audit('LOGIN_SUCCESS', f"User {user.username} logged in")
        flash(f'Welcome back, {user.full_name}!', 'success')
        
        if user.is_admin:
            return redirect(url_for('admin_dashboard'))
        return redirect(url_for('customer_dashboard'))
    
    # Failed login
    app.logger.warning(f"Failed login attempt for username: {username}")
    flash('Invalid username or password.', 'error')
    return redirect(url_for('index'))

@app.route('/register', methods=['GET', 'POST'])
def register():
    """New customer registration - keeps all original fields"""
    if request.method == 'POST':
        # Get all original form data
        username = request.form.get('username', '').strip()
        email = request.form.get('email', '').strip().lower()
        password = request.form.get('password', '')
        confirm_password = request.form.get('confirm_password', '')
        full_name = request.form.get('full_name', '').strip()
        company = request.form.get('company', '').strip()
        phone = request.form.get('phone', '').strip()
        
        # Sensitive data (kept for demo)
        ssn = request.form.get('ssn', '').strip()
        credit_card = request.form.get('credit_card', '').strip()
        card_expiry = request.form.get('card_expiry', '').strip()
        card_cvv = request.form.get('card_cvv', '').strip()
        
        # Address
        address = request.form.get('address', '').strip()
        city = request.form.get('city', '').strip()
        state = request.form.get('state', '').strip()
        zip_code = request.form.get('zip_code', '').strip()
        country = request.form.get('country', '').strip()
        
        account_type = request.form.get('account_type', 'individual')
        
        # Basic validation
        if not all([username, email, password, full_name]):
            flash('Please fill in all required fields.', 'error')
            return render_template('register.html')
        
        if password != confirm_password:
            flash('Passwords do not match.', 'error')
            return render_template('register.html')
        
        # Check email format
        if not re.match(r"[^@]+@[^@]+\.[^@]+", email):
            flash('Invalid email format.', 'error')
            return render_template('register.html')
        
        existing = User.query.filter(
            (User.username == username) | (User.email == email)
        ).first()
        
        if existing:
            flash('Username or email already exists.', 'error')
            return render_template('register.html')
        
        try:
            # Create new user with all original fields
            new_user = User(
                username=username,
                email=email,
                full_name=full_name,
                company=company if company else None,
                phone=phone if phone else None,
                ssn=ssn if ssn else None,
                credit_card_number=credit_card if credit_card else None,
                credit_card_expiry=card_expiry if card_expiry else None,
                credit_card_cvv=card_cvv if card_cvv else None,
                address=address if address else None,
                city=city if city else None,
                state=state if state else None,
                zip_code=zip_code if zip_code else None,
                country=country if country else None,
                account_type=account_type,
                is_verified=False
            )
            new_user.set_password(password)
            
            db.session.add(new_user)
            db.session.commit()
            
            log_audit('USER_REGISTERED', f"New user registered: {username}")
            flash('Registration successful! Please wait for account verification.', 'success')
            return redirect(url_for('index'))
            
        except Exception as e:
            db.session.rollback()
            app.logger.error(f"Registration error: {str(e)}")
            flash('An error occurred during registration. Please try again.', 'error')
        
        return render_template('register.html')
    
    return render_template('register.html')

@app.route('/forgot-password', methods=['GET', 'POST'])
def forgot_password():
    """Password reset request"""
    if request.method == 'POST':
        email = request.form.get('email', '').strip().lower()
        
        # SECURE: Don't reveal if email exists
        user = User.query.filter_by(email=email).first()
        
        if user:
            # Generate reset token
            token = secrets.token_urlsafe(32)
            user.password_reset_token = token
            user.password_reset_expires = datetime.utcnow() + timedelta(hours=24)
            db.session.commit()
            
            # In production, send email
            print(f"🔐 PASSWORD RESET LINK: http://localhost:5000/reset-password/{token}")
        
        # Always show same message
        flash('If your email is registered, you will receive a password reset link.', 'info')
        return redirect(url_for('index'))
    
    return render_template('forgot-password.html')

@app.route('/reset-password/<token>', methods=['GET', 'POST'])
def reset_password(token):
    """Password reset"""
    user = User.query.filter_by(password_reset_token=token).first()
    
    if not user or not user.password_reset_expires or user.password_reset_expires < datetime.utcnow():
        flash('Invalid or expired reset token.', 'error')
        return redirect(url_for('index'))
    
    if request.method == 'POST':
        new_password = request.form.get('new_password', '')
        confirm_password = request.form.get('confirm_password', '')
        
        if new_password != confirm_password:
            flash('Passwords do not match.', 'error')
            return render_template('password-reset-confirm.html', token=token)
        
        # Update password
        user.set_password(new_password)
        user.password_reset_token = None
        user.password_reset_expires = None
        db.session.commit()
        
        flash('Password updated successfully! You can now login.', 'success')
        return redirect(url_for('index'))
    
    return render_template('password-reset-confirm.html', token=token)

@app.route('/logout')
def logout():
    """Log out user"""
    if 'user_id' in session:
        log_audit('LOGOUT', f"User logged out")
    
    session.clear()
    flash('You have been logged out.', 'info')
    return redirect(url_for('index'))

# ==================== CUSTOMER ROUTES ====================

@app.route('/customer/dashboard')
@login_required
def customer_dashboard():
    """Customer Dashboard - with all original features"""
    user = db.session.get(User, session['user_id'])
    if not user:
        session.clear()
        return redirect(url_for('index'))
    
    # Get ticket statistics (matching original)
    total_tickets = Ticket.query.filter_by(customer_id=user.id).count()
    open_tickets = Ticket.query.filter_by(customer_id=user.id, status='Open').count()
    in_progress_tickets = Ticket.query.filter_by(customer_id=user.id, status='In Progress').count()
    resolved_this_month = Ticket.query.filter(
        Ticket.customer_id == user.id,
        Ticket.status == 'Resolved',
        Ticket.resolved_at >= datetime.utcnow().replace(day=1, hour=0, minute=0, second=0, microsecond=0)
    ).count()
    
    # Calculate average response time
    tickets_with_response = Ticket.query.filter(
        Ticket.customer_id == user.id,
        Ticket.first_response_at.isnot(None)
    ).all()
    
    if tickets_with_response:
        total_response_time = sum([(t.first_response_at - t.created_at).total_seconds() / 3600 
                                  for t in tickets_with_response if t.first_response_at])
        avg_response_time = round(total_response_time / len(tickets_with_response), 1)
    else:
        avg_response_time = 2.4  # Default demo value
    
    stats = {
        'total_tickets': total_tickets,
        'open_tickets': open_tickets,
        'in_progress_tickets': in_progress_tickets,
        'resolved_this_month': resolved_this_month,
        'avg_response_time': avg_response_time
    }
    
    # Get recent tickets
    recent_tickets = Ticket.query.filter_by(customer_id=user.id)\
        .order_by(Ticket.created_at.desc())\
        .limit(5).all()
    
    # Get unread notifications
    notifications = Notification.query.filter_by(
        user_id=user.id, is_read=False
    ).order_by(Notification.created_at.desc()).limit(5).all()
    unread_count = Notification.query.filter_by(user_id=user.id, is_read=False).count()
    
    # Get active announcements
    announcements = Announcement.query.filter_by(is_active=True)\
        .order_by(Announcement.priority.desc(), Announcement.created_at.desc())\
        .limit(3).all()
    
    # Get upcoming maintenance
    upcoming_maintenance = Maintenance.query.filter(
        Maintenance.scheduled_start >= datetime.utcnow(),
        Maintenance.status.in_(['scheduled', 'in-progress'])
    ).order_by(Maintenance.scheduled_start).limit(2).all()
    
    # System status (matching original)
    system_status = {
        'support': 'operational',
        'api': 'operational',
        'portal': 'operational',
        'database': 'degraded'
    }
    
    return render_template(
        'customer/dashboard.html',
        user=user,
        stats=stats,
        recent_tickets=recent_tickets,
        notifications=notifications,
        unread_count=unread_count,
        announcements=announcements,
        upcoming_maintenance=upcoming_maintenance,
        system_status=system_status
    )

@app.route('/customer/profile')
@login_required
def customer_profile():
    """Customer profile page"""
    user = db.session.get(User, session['user_id'])
    if not user:
        session.clear()
        return redirect(url_for('index'))
    
    return render_template('customer/profile.html', user=user)

@app.route('/customer/profile/update', methods=['POST'])
@login_required
def update_profile():
    """Update user profile"""
    user = db.session.get(User, session['user_id'])
    if not user:
        flash('User not found.', 'error')
        return redirect(url_for('logout'))
    
    # Update allowed fields
    user.full_name = request.form.get('full_name', user.full_name).strip()[:100]
    user.company = request.form.get('company', user.company).strip()[:100] if request.form.get('company') else None
    user.phone = request.form.get('phone', user.phone).strip()[:20] if request.form.get('phone') else None
    user.address = request.form.get('address', user.address).strip()[:200] if request.form.get('address') else None
    user.city = request.form.get('city', user.city).strip()[:50] if request.form.get('city') else None
    user.state = request.form.get('state', user.state).strip()[:20] if request.form.get('state') else None
    user.zip_code = request.form.get('zip_code', user.zip_code).strip()[:10] if request.form.get('zip_code') else None
    user.country = request.form.get('country', user.country).strip()[:50] if request.form.get('country') else None
    
    db.session.commit()
    
    log_audit('PROFILE_UPDATED', f"User {user.username} updated profile")
    flash('Profile updated successfully!', 'success')
    return redirect(url_for('customer_profile'))

@app.route('/customer/change-password', methods=['POST'])
@login_required
def change_password():
    """Change user password"""
    user = db.session.get(User, session['user_id'])
    if not user:
        flash('User not found.', 'error')
        return redirect(url_for('logout'))
    
    current = request.form.get('current_password', '')
    new = request.form.get('new_password', '')
    confirm = request.form.get('confirm_password', '')
    
    # Verify current password
    if not user.check_password(current):
        flash('Current password is incorrect.', 'error')
        return redirect(url_for('customer_profile'))
    
    if new != confirm:
        flash('New passwords do not match.', 'error')
        return redirect(url_for('customer_profile'))
    
    if len(new) < 8:
        flash('Password must be at least 8 characters long.', 'error')
        return redirect(url_for('customer_profile'))
    
    user.set_password(new)
    db.session.commit()
    
    log_audit('PASSWORD_CHANGED', f"User {user.username} changed password")
    flash('Password changed successfully!', 'success')
    return redirect(url_for('customer_profile'))

@app.route('/customer/tickets')
@login_required
def customer_tickets():
    """View all tickets with filtering"""
    user = db.session.get(User, session['user_id'])
    if not user:
        session.clear()
        return redirect(url_for('index'))
    
    # Get filter parameters
    search = request.args.get('search', '')
    status = request.args.get('status', 'all')
    priority = request.args.get('priority', 'all')
    category = request.args.get('category', 'all')
    date_from = request.args.get('date_from', '')
    date_to = request.args.get('date_to', '')
    sort_by = request.args.get('sort_by', 'newest')
    page = request.args.get('page', 1, type=int)
    per_page = 10
    
    # Base query
    query = Ticket.query.filter_by(customer_id=user.id)
    
    # Apply filters
    if search:
        search_pattern = f"%{search}%"
        query = query.filter(
            (Ticket.subject.ilike(search_pattern)) | 
            (Ticket.description.ilike(search_pattern)) |
            (Ticket.ticket_number.ilike(search_pattern))
        )
    
    if status != 'all':
        query = query.filter(Ticket.status == status)
    
    if priority != 'all':
        query = query.filter(Ticket.priority == priority)
    
    if category != 'all':
        query = query.filter(Ticket.category == category)
    
    # Date filtering
    if date_from:
        try:
            date_from_obj = datetime.strptime(date_from, '%Y-%m-%d')
            query = query.filter(Ticket.created_at >= date_from_obj)
        except ValueError:
            flash('Invalid date format. Use YYYY-MM-DD.', 'error')
    
    if date_to:
        try:
            date_to_obj = datetime.strptime(date_to, '%Y-%m-%d')
            date_to_end = date_to_obj + timedelta(days=1)
            query = query.filter(Ticket.created_at <= date_to_end)
        except ValueError:
            flash('Invalid date format. Use YYYY-MM-DD.', 'error')
    
    # Sorting
    if sort_by == 'newest':
        query = query.order_by(Ticket.created_at.desc())
    elif sort_by == 'oldest':
        query = query.order_by(Ticket.created_at.asc())
    elif sort_by == 'last_updated':
        query = query.order_by(Ticket.updated_at.desc())
    
    # Pagination
    pagination = query.paginate(page=page, per_page=per_page, error_out=False)
    
    # Get unique categories for filter
    categories = db.session.query(Ticket.category)\
        .filter_by(customer_id=user.id)\
        .distinct().all()
    categories = [c[0] for c in categories if c[0]]
    
    return render_template(
        'customer/tickets.html',
        user=user,
        tickets=pagination.items,
        pagination=pagination,
        categories=categories,
        filters={
            'search': search,
            'status': status,
            'priority': priority,
            'category': category,
            'date_from': date_from,
            'date_to': date_to,
            'sort_by': sort_by
        }
    )

@app.route('/customer/new-ticket', methods=['GET', 'POST'])
@login_required
def new_ticket():
    """Create a new support ticket"""
    user = db.session.get(User, session['user_id'])
    if not user:
        session.clear()
        return redirect(url_for('index'))
    
    if request.method == 'POST':
        # Get form data
        subject = request.form.get('subject', '').strip()
        category = request.form.get('category', '').strip()
        description = request.form.get('description', '').strip()
        
        if not subject or not category or not description:
            flash('Please fill in all required fields.', 'error')
            return render_template('customer/new-ticket.html', user=user)
        
        try:
            # Generate ticket number
            ticket_number = generate_ticket_number()
            
            # Create ticket
            ticket = Ticket(
                ticket_number=ticket_number,
                customer_id=user.id,
                subject=subject,
                description=description,
                category=category,
                priority='Medium',
                status='Open'
            )
            
            # Handle file upload
            if 'attachment' in request.files:
                file = request.files['attachment']
                if file and file.filename:
                    try:
                        filename, original_filename = save_uploaded_file(file)
                        if filename:
                            ticket.attachment_path = filename
                    except ValueError as e:
                        flash(str(e), 'error')
                        return render_template('customer/new-ticket.html', user=user)
            
            db.session.add(ticket)
            db.session.commit()
            
            # Create notification
            notification = Notification(
                user_id=user.id,
                title='Ticket Created',
                message=f'Ticket #{ticket_number} has been created successfully.',
                type='success',
                link=f'/customer/ticket/{ticket_number}'
            )
            db.session.add(notification)
            db.session.commit()
            
            log_audit('TICKET_CREATED', f"Ticket {ticket_number} created")
            flash(f'Ticket #{ticket_number} created successfully!', 'success')
            return redirect(url_for('customer_ticket_detail', ticket_number=ticket_number))
            
        except Exception as e:
            db.session.rollback()
            app.logger.error(f"Ticket creation error: {str(e)}")
            flash('Error creating ticket. Please try again.', 'error')
    
    return render_template('customer/new-ticket.html', user=user)

@app.route('/customer/ticket/<ticket_number>')
@login_required
def customer_ticket_detail(ticket_number):
    """View single ticket details"""
    user = db.session.get(User, session['user_id'])
    if not user:
        session.clear()
        return redirect(url_for('index'))
    
    # SECURE: Using ORM, not raw SQL
    ticket = Ticket.query.filter_by(ticket_number=ticket_number).first_or_404()
    
    # Verify access
    if not ticket.can_access(user):
        abort(403)
    
    # Get messages
    messages = TicketMessage.query.filter_by(ticket_id=ticket.id)\
        .order_by(TicketMessage.created_at).all()
    
    # Filter internal messages for non-admins
    if not user.is_admin:
        messages = [m for m in messages if not m.is_internal]
    
    # Get agent info
    agent = None
    if ticket.assigned_to:
        agent = db.session.get(User, ticket.assigned_to)
    
    return render_template(
        'customer/ticket-detail.html',
        user=user,
        ticket=ticket,
        messages=messages,
        agent=agent
    )

@app.route('/customer/ticket/<ticket_number>/reply', methods=['POST'])
@login_required
def ticket_reply(ticket_number):
    """Add a reply to a ticket"""
    user = db.session.get(User, session['user_id'])
    if not user:
        flash('Please login again.', 'error')
        return redirect(url_for('logout'))
    
    ticket = Ticket.query.filter_by(ticket_number=ticket_number).first_or_404()
    
    # Verify access
    if not ticket.can_access(user):
        abort(403)
    
    message = request.form.get('message', '').strip()
    if not message:
        flash('Message cannot be empty.', 'error')
        return redirect(url_for('customer_ticket_detail', ticket_number=ticket_number))
    
    try:
        # Create message
        new_message = TicketMessage(
            ticket_id=ticket.id,
            author_id=user.id,
            message=message,
            is_internal=False
        )
        
        db.session.add(new_message)
        
        # Update ticket
        if ticket.status == 'Closed':
            ticket.status = 'Open'
        ticket.updated_at = datetime.utcnow()
        
        db.session.commit()
        
        log_audit('TICKET_REPLIED', f"Reply added to ticket {ticket_number}")
        flash('Reply added successfully.', 'success')
        
    except Exception as e:
        db.session.rollback()
        app.logger.error(f"Reply error: {str(e)}")
        flash('Error adding reply. Please try again.', 'error')
    
    return redirect(url_for('customer_ticket_detail', ticket_number=ticket_number))

@app.route('/customer/ticket/<ticket_number>/attachment')
@login_required
def download_attachment(ticket_number):
    """Download ticket attachment - SECURE version"""
    user = db.session.get(User, session['user_id'])
    if not user:
        return redirect(url_for('logout'))
    
    ticket = Ticket.query.filter_by(ticket_number=ticket_number).first_or_404()
    
    # Verify access
    if not ticket.can_access(user):
        abort(403)
    
    if not ticket.attachment_path:
        flash('No attachment found.', 'error')
        return redirect(url_for('customer_ticket_detail', ticket_number=ticket_number))
    
    # SECURE: Get safe file path
    file_path = get_safe_file_path(ticket.attachment_path, UPLOAD_FOLDER)
    
    if file_path and os.path.exists(file_path):
        log_audit('FILE_DOWNLOADED', f"Downloaded {ticket.attachment_path} from ticket {ticket_number}")
        return send_file(
            file_path,
            as_attachment=True,
            download_name=ticket.attachment_path.split('_', 2)[-1] if '_' in ticket.attachment_path else ticket.attachment_path,
            mimetype='application/octet-stream'
        )
    else:
        flash('File not found.', 'error')
        return redirect(url_for('customer_ticket_detail', ticket_number=ticket_number))

@app.route('/customer/billing')
@login_required
def customer_billing():
    """Billing page"""
    user = db.session.get(User, session['user_id'])
    if not user:
        session.clear()
        return redirect(url_for('index'))
    
    # Get payment methods
    payment_methods = PaymentMethod.query.filter_by(user_id=user.id).all()
    
    # Get invoices
    invoices = Invoice.query.filter_by(user_id=user.id)\
        .order_by(Invoice.issue_date.desc()).all()
    
    # Calculate balance
    current_balance = sum(inv.total for inv in invoices if inv.status == 'pending')
    
    return render_template(
        'customer/billing.html',
        user=user,
        payment_methods=payment_methods,
        invoices=invoices,
        current_balance=current_balance
    )

@app.route('/customer/notifications/mark-read/<int:notification_id>', methods=['POST'])
@login_required
def mark_notification_read(notification_id):
    """Mark notification as read"""
    notification = Notification.query.get_or_404(notification_id)
    
    if notification.user_id != session['user_id']:
        return jsonify({'error': 'Unauthorized'}), 403
    
    notification.is_read = True
    db.session.commit()
    
    return jsonify({'success': True})

@app.route('/customer/notifications/mark-all-read', methods=['POST'])
@login_required
def mark_all_notifications_read():
    """Mark all notifications as read"""
    Notification.query.filter_by(
        user_id=session['user_id'],
        is_read=False
    ).update({'is_read': True})
    
    db.session.commit()
    return jsonify({'success': True})

@app.route('/customer/knowledge-base')
@login_required
def knowledge_base():
    """Knowledge base - File-based version"""
    user = db.session.get(User, session['user_id'])
    
    # Get filename parameter
    filename = request.args.get('file')
    
    # If file parameter exists, display that file
    if filename:
        return display_kb_file_secure(filename)
    
    # Otherwise show the file list
    files = get_kb_files()
    
    return render_template('customer/knowledge-base.html', 
                         user=user,
                         files=files)


def display_kb_file_secure(filename):
    """Securely display knowledge base file with better error handling"""
    user = db.session.get(User, session['user_id'])
    
    # Security checks
    if not filename or '..' in filename or filename.startswith('/'):
        flash('Invalid file request.', 'error')
        return redirect(url_for('knowledge_base'))
    
    # Safe path validation
    safe_filename = os.path.basename(filename)
    file_path = os.path.join(KNOWLEDGE_BASE_FOLDER, safe_filename)
    
    # Debug info (remove in production)
    # print(f"🔍 Attempting to read: {file_path}")
    # print(f"🔍 File exists: {os.path.exists(file_path)}")
    
    if not is_safe_path(KNOWLEDGE_BASE_FOLDER, safe_filename):
        flash('Access denied.', 'error')
        return redirect(url_for('knowledge_base'))
    
    if not os.path.exists(file_path):
        flash(f'File not found: {safe_filename}', 'error')
        return redirect(url_for('knowledge_base'))
    
    if not os.path.isfile(file_path):
        flash('Not a valid file.', 'error')
        return redirect(url_for('knowledge_base'))
    
    # Check file size
    file_size = os.path.getsize(file_path)
    if file_size > 10 * 1024 * 1024:  # 10MB limit
        flash('File too large to display.', 'error')
        return redirect(url_for('knowledge_base'))
    
    # Try different encodings
    encodings = ['utf-8', 'latin-1', 'cp1252', 'iso-8859-1']
    content = None
    used_encoding = None
    
    for encoding in encodings:
        try:
            with open(file_path, 'r', encoding=encoding) as f:
                content = f.read()
            used_encoding = encoding
            break
        except UnicodeDecodeError:
            continue
        except Exception as e:
            print(f"❌ Error with {encoding}: {e}")
            continue
    
    if content is None:
        # Try reading as binary
        try:
            with open(file_path, 'rb') as f:
                binary_content = f.read()
            # Try to decode as much as possible
            content = binary_content.decode('utf-8', errors='replace')
            used_encoding = 'utf-8 (with replacements)'
        except Exception as e:
            flash(f'Cannot read file: {str(e)}', 'error')
            return redirect(url_for('knowledge_base'))
    
    # Convert markdown to HTML if needed
    ext = os.path.splitext(safe_filename)[1].lower()
    if ext == '.md':
        import markdown
        content = markdown.markdown(content)
    
    # Log success
    # print(f"Successfully read {safe_filename} with {used_encoding}")
    
    return render_template('customer/view_file.html',
                         user=user,
                         filename=safe_filename,
                         title=safe_filename.replace('_', ' ').replace('-', ' '),
                         content=content,
                         file_type=ext)

@app.route('/customer/knowledge-base/download/<filename>')
@login_required
def download_kb_file(filename):
    """Download knowledge base file"""
    # Security checks
    if '..' in filename or filename.startswith('/'):
        abort(404)
    
    safe_filename = os.path.basename(filename)
    file_path = os.path.join(KNOWLEDGE_BASE_FOLDER, safe_filename)
    
    if not is_safe_path(KNOWLEDGE_BASE_FOLDER, safe_filename):
        abort(404)
    
    if not os.path.exists(file_path):
        abort(404)
    
    from flask import send_file
    return send_file(file_path, as_attachment=True)



@app.route('/customer/ping', methods=['POST'])
@login_required
def ping_host():
    """Network diagnostics tool - SECURE version with command injection protection"""
    host = request.form.get('host', '').strip()
    
    if not host:
        flash('Please enter a hostname or IP address.', 'error')
        return redirect(url_for('customer_dashboard'))
    
    # SECURITY: Validate and sanitize input
    # Only allow domain names and IP addresses
    if not re.match(r'^[a-zA-Z0-9\.\-]+$', host):
        flash('Invalid host format. Only alphanumeric characters, dots, and hyphens are allowed.', 'error')
        return redirect(url_for('customer_dashboard'))
    
    # Block command injection attempts
    dangerous_chars = [';', '&', '|', '`', '$', '(', ')', '{', '}', '[', ']', '<', '>', '!', '#', '*', '?', '~']
    if any(char in host for char in dangerous_chars):
        flash('Invalid characters detected in host input.', 'error')
        return redirect(url_for('customer_dashboard'))
    
    # Store target for display
    session['ping_target'] = host
    
    # SECURE: Use shlex.quote to escape the host parameter
    safe_host = shlex.quote(host)
    
    # Use parameterized command with shlex to prevent injection
    try:
        # SECURE: Use list form of subprocess.run to avoid shell injection
        # This is the most secure way to run subprocesses
        result = subprocess.run(
            ['ping', '-c', '4', host],  # Using list form, not shell=True
            capture_output=True,
            text=True,
            timeout=10
        )
        
        terminal_output = f"$ ping -c 4 {host}\n\n"
        terminal_output += result.stdout
        
        if result.stderr:
            terminal_output += f"\n[stderr]\n{result.stderr}"
        
        # Parse output for status
        if result.returncode == 0:
            session['ping_status'] = 'UP'
            session['ping_result'] = terminal_output + f"\n\n✅ Exit status: {result.returncode} (success)"
        else:
            session['ping_status'] = 'DOWN'
            session['ping_result'] = terminal_output + f"\n\n❌ Exit status: {result.returncode} (failed)"
        
        # Try to extract packet info
        output = result.stdout.lower()
        packet_match = re.search(r'(\d+) packets? transmitted, (\d+)\s*(received|packets? received)', output)
        if packet_match:
            session['ping_packets'] = f"{packet_match.group(2)}/{packet_match.group(1)}"
        
        # Try to extract time
        time_match = re.search(r'time[=<]\s*(\d+\.?\d*)\s*ms', output)
        if time_match:
            session['ping_time'] = f"{time_match.group(1)}ms"
        
    except subprocess.TimeoutExpired:
        session['ping_error'] = "Request timed out after 10 seconds."
        session['ping_status'] = 'UNKNOWN'
    except Exception as e:
        session['ping_error'] = f"Error: {str(e)}"
        session['ping_status'] = 'UNKNOWN'
        app.logger.error(f"Ping error: {str(e)}")
    
    return redirect(url_for('customer_dashboard'))

# ==================== ADMIN ROUTES ====================

@app.route('/admin/dashboard')
@admin_required
def admin_dashboard():
    """Admin Dashboard"""
    user = db.session.get(User, session['user_id'])
    
    # Get statistics
    stats = {
        'total_users': User.query.count(),
        'total_tickets': Ticket.query.count(),
        'open_tickets': Ticket.query.filter_by(status='Open').count(),
        'unread_notifications': Notification.query.filter_by(is_read=False).count(),
    }
    
    # Get recent tickets
    recent_tickets = Ticket.query.order_by(Ticket.created_at.desc()).limit(10).all()
    
    # Get recent users
    recent_users = User.query.order_by(User.created_at.desc()).limit(10).all()
    
    return render_template(
        'admin/dashboard.html',
        user=user,
        stats=stats,
        recent_tickets=recent_tickets,
        recent_users=recent_users
    )

@app.route('/admin/users')
@admin_required
def admin_users():
    """Admin user management"""
    page = request.args.get('page', 1, type=int)
    per_page = 20
    
    search = request.args.get('search', '')
    
    query = User.query
    if search:
        search_pattern = f"%{search}%"
        query = query.filter(
            (User.username.ilike(search_pattern)) |
            (User.email.ilike(search_pattern)) |
            (User.full_name.ilike(search_pattern))
        )
    
    pagination = query.order_by(User.created_at.desc())\
        .paginate(page=page, per_page=per_page, error_out=False)
    
    return render_template(
        'admin/users.html',
        users=pagination.items,
        pagination=pagination,
        search=search
    )

@app.route('/admin/user/<int:user_id>')
@admin_required
def admin_user_detail(user_id):
    """View user details"""
    user = db.session.get(User, user_id)
    if not user:
        abort(404)
    
    # Get user's tickets
    tickets = Ticket.query.filter_by(customer_id=user.id)\
        .order_by(Ticket.created_at.desc()).all()
    
    return render_template(
        'admin/user-detail.html',
        target_user=user,
        tickets=tickets
    )

@app.route('/admin/tickets')
@admin_required
def admin_tickets():
    """Admin ticket management"""
    page = request.args.get('page', 1, type=int)
    per_page = 20
    
    status = request.args.get('status', 'all')
    priority = request.args.get('priority', 'all')
    
    query = Ticket.query
    
    if status != 'all':
        query = query.filter(Ticket.status == status)
    
    if priority != 'all':
        query = query.filter(Ticket.priority == priority)
    
    pagination = query.order_by(Ticket.created_at.desc())\
        .paginate(page=page, per_page=per_page, error_out=False)
    
    return render_template(
        'admin/tickets.html',
        tickets=pagination.items,
        pagination=pagination,
        filters={'status': status, 'priority': priority}
    )

@app.route('/admin/ticket/<ticket_number>')
@admin_required
def admin_ticket_detail(ticket_number):
    """View ticket details (admin)"""
    ticket = Ticket.query.filter_by(ticket_number=ticket_number).first_or_404()
    
    # Get all messages (including internal)
    messages = TicketMessage.query.filter_by(ticket_id=ticket.id)\
        .order_by(TicketMessage.created_at).all()
    
    # Get customer and agent info
    customer = db.session.get(User, ticket.customer_id)
    agent = db.session.get(User, ticket.assigned_to) if ticket.assigned_to else None
    
    # Get available agents for assignment
    agents = User.query.filter_by(is_admin=True).all()
    
    return render_template(
        'admin/ticket-detail.html',
        ticket=ticket,
        messages=messages,
        customer=customer,
        agent=agent,
        agents=agents
    )

@app.route('/admin/ticket/<ticket_number>/reply', methods=['POST'])
@admin_required
def admin_ticket_reply(ticket_number):
    """Add admin reply to ticket"""
    ticket = Ticket.query.filter_by(ticket_number=ticket_number).first_or_404()
    
    message = request.form.get('message', '').strip()
    is_internal = request.form.get('is_internal') == 'on'
    
    if not message:
        flash('Message cannot be empty.', 'error')
        return redirect(url_for('admin_ticket_detail', ticket_number=ticket_number))
    
    try:
        # Create message
        new_message = TicketMessage(
            ticket_id=ticket.id,
            author_id=session['user_id'],
            message=message,
            is_internal=is_internal
        )
        
        db.session.add(new_message)
        ticket.updated_at = datetime.utcnow()
        
        # If it's the first response, record it
        if not ticket.first_response_at:
            ticket.first_response_at = datetime.utcnow()
            response_time = (ticket.first_response_at - ticket.created_at).total_seconds() / 60
            ticket.response_time_minutes = int(response_time)
        
        db.session.commit()
        
        log_audit('TICKET_ADMIN_REPLIED', f"Admin reply to ticket {ticket_number}")
        flash('Reply added successfully.', 'success')
        
    except Exception as e:
        db.session.rollback()
        app.logger.error(f"Admin reply error: {str(e)}")
        flash('Error adding reply.', 'error')
    
    return redirect(url_for('admin_ticket_detail', ticket_number=ticket_number))

# ==================== ERROR HANDLERS ====================

@app.errorhandler(400)
def bad_request_error(error):
    """Handle 400 errors"""
    return render_template('errors/400.html'), 400

@app.errorhandler(403)
def forbidden_error(error):
    """Handle 403 errors"""
    return render_template('errors/403.html'), 403

@app.errorhandler(404)
def not_found_error(error):
    """Handle 404 errors"""
    return render_template('errors/404.html'), 404

@app.errorhandler(500)
def internal_error(error):
    """Handle 500 errors"""
    db.session.rollback()
    app.logger.error(f"Server Error: {error}")
    return render_template('errors/500.html'), 500

# ==================== TEMPLATE FILTERS ====================

@app.template_filter('format_datetime')
def format_datetime(value, format='%b %d, %Y %I:%M %p'):
    """Format datetime safely"""
    if value is None:
        return ''
    
    if isinstance(value, str):
        try:
            from dateutil import parser
            value = parser.parse(value)
        except:
            return value
    
    if hasattr(value, 'strftime'):
        return value.strftime(format)
    
    return str(value)

@app.template_filter('truncate')
def truncate(text, length=100):
    """Truncate text safely"""
    if not text or len(text) <= length:
        return text
    return text[:length] + '...'

# ==================== RUN APPLICATION ====================

if __name__ == '__main__':
    # Never run with debug=True in production
    debug_mode = os.environ.get('FLASK_ENV') == 'development'
    app.run(debug=debug_mode, host='0.0.0.0', port=5000)