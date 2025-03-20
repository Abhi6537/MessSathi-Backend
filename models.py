from flask_sqlalchemy import SQLAlchemy
from datetime import datetime
from werkzeug.security import generate_password_hash, check_password_hash
from geoalchemy2 import Geometry
import enum

db = SQLAlchemy()

class UserType(enum.Enum):
    TENANT = "tenant"
    OWNER = "owner"

class User(db.Model):
    __tablename__ = 'users'
    
    id = db.Column(db.Integer, primary_key=True)
    email = db.Column(db.String(120), unique=True, nullable=False)
    name = db.Column(db.String(100), nullable=False)
    password_hash = db.Column(db.String(200), nullable=False)
    phone = db.Column(db.String(20), nullable=True)
    user_type = db.Column(db.Enum(UserType), nullable=False)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    last_login = db.Column(db.DateTime, nullable=True)
    
    # Relationships
    tenant_profile = db.relationship('TenantProfile', backref='user', uselist=False, cascade="all, delete-orphan")
    owner_profile = db.relationship('OwnerProfile', backref='user', uselist=False, cascade="all, delete-orphan")
    mess_listings = db.relationship('MessListing', backref='owner', lazy=True)
    saved_messes = db.relationship('SavedMess', backref='user', lazy=True)
    inquiries_sent = db.relationship('Inquiry', backref='sender', lazy=True, foreign_keys='Inquiry.sender_id')
    
    def set_password(self, password):
        self.password_hash = generate_password_hash(password)
        
    def check_password(self, password):
        return check_password_hash(self.password_hash, password)

class TenantProfile(db.Model):
    __tablename__ = 'tenant_profiles'
    
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('users.id'), nullable=False)
    current_location = db.Column(Geometry('POINT'), nullable=True)
    address = db.Column(db.Text, nullable=True)
    preferred_area = db.Column(db.String(100), nullable=True)
    preferred_rent_min = db.Column(db.Integer, nullable=True)
    preferred_rent_max = db.Column(db.Integer, nullable=True)
    preferred_room_type = db.Column(db.String(50), nullable=True)
    
class OwnerProfile(db.Model):
    __tablename__ = 'owner_profiles'
    
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('users.id'), nullable=False)
    business_name = db.Column(db.String(100), nullable=True)
    address = db.Column(db.Text, nullable=True)

class MessListing(db.Model):
    __tablename__ = 'mess_listings'
    
    id = db.Column(db.Integer, primary_key=True)
    owner_id = db.Column(db.Integer, db.ForeignKey('users.id'), nullable=False)
    title = db.Column(db.String(100), nullable=False)
    description = db.Column(db.Text, nullable=False)
    address = db.Column(db.Text, nullable=False)
    locality = db.Column(db.String(100), nullable=False)
    city = db.Column(db.String(50), nullable=False)
    state = db.Column(db.String(50), nullable=False)
    pincode = db.Column(db.String(20), nullable=False)
    contact_person = db.Column(db.String(100), nullable=True)
    contact_phone = db.Column(db.String(20), nullable=False)
    contact_email = db.Column(db.String(120), nullable=True)
    location = db.Column(db.String(50), nullable=False)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    updated_at = db.Column(db.DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)
    is_active = db.Column(db.Boolean, default=True)
    rating = db.Column(db.Float, default=0.0)
    reviews_count = db.Column(db.Integer, default=0)
    
    # Relationships
    rooms = db.relationship('Room', backref='mess_listing', lazy=True, cascade="all, delete-orphan")
    photos = db.relationship('MessPhoto', backref='mess_listing', lazy=True, cascade="all, delete-orphan")
    amenities = db.relationship('MessAmenity', backref='mess_listing', lazy=True, cascade="all, delete-orphan")
    rules = db.relationship('MessRule', backref='mess_listing', lazy=True, cascade="all, delete-orphan")
    inquiries = db.relationship('Inquiry', backref='mess_listing', lazy=True)
    reviews = db.relationship('Review', backref='mess_listing', lazy=True)

class Room(db.Model):
    __tablename__ = 'rooms'
    
    id = db.Column(db.Integer, primary_key=True)
    mess_id = db.Column(db.Integer, db.ForeignKey('mess_listings.id'), nullable=False)
    room_type = db.Column(db.String(50), nullable=False)  # 'single', 'double', 'triple', 'dormitory'
    rent = db.Column(db.Integer, nullable=False)
    capacity = db.Column(db.Integer, nullable=False)  # Number of tenants per room
    available_count = db.Column(db.Integer, nullable=False)  # Available rooms of this type
    total_count = db.Column(db.Integer, nullable=False)  # Total rooms of this type

class MessPhoto(db.Model):
    __tablename__ = 'mess_photos'
    
    id = db.Column(db.Integer, primary_key=True)
    mess_id = db.Column(db.Integer, db.ForeignKey('mess_listings.id'), nullable=False)
    photo_url = db.Column(db.String(255), nullable=False)
    is_primary = db.Column(db.Boolean, default=False)
    uploaded_at = db.Column(db.DateTime, default=datetime.utcnow)

class MessAmenity(db.Model):
    __tablename__ = 'mess_amenities'
    
    id = db.Column(db.Integer, primary_key=True)
    mess_id = db.Column(db.Integer, db.ForeignKey('mess_listings.id'), nullable=False)
    amenity = db.Column(db.String(100), nullable=False)

class MessRule(db.Model):
    __tablename__ = 'mess_rules'
    
    id = db.Column(db.Integer, primary_key=True)
    mess_id = db.Column(db.Integer, db.ForeignKey('mess_listings.id'), nullable=False)
    rule = db.Column(db.String(255), nullable=False)

class SavedMess(db.Model):
    __tablename__ = 'saved_messes'
    
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('users.id'), nullable=False)
    mess_id = db.Column(db.Integer, db.ForeignKey('mess_listings.id'), nullable=False)
    saved_at = db.Column(db.DateTime, default=datetime.utcnow)
    
    # Relationship to fetch mess details
    mess = db.relationship('MessListing')

class Inquiry(db.Model):
    __tablename__ = 'inquiries'
    
    id = db.Column(db.Integer, primary_key=True)
    mess_id = db.Column(db.Integer, db.ForeignKey('mess_listings.id'), nullable=False)
    sender_id = db.Column(db.Integer, db.ForeignKey('users.id'), nullable=False)
    message = db.Column(db.Text, nullable=False)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    is_read = db.Column(db.Boolean, default=False)
    response = db.Column(db.Text, nullable=True)
    response_at = db.Column(db.DateTime, nullable=True)

class Review(db.Model):
    __tablename__ = 'reviews'
    
    id = db.Column(db.Integer, primary_key=True)
    mess_id = db.Column(db.Integer, db.ForeignKey('mess_listings.id'), nullable=False)
    user_id = db.Column(db.Integer, db.ForeignKey('users.id'), nullable=False)
    rating = db.Column(db.Integer, nullable=False)  # 1-5 stars
    comment = db.Column(db.Text, nullable=True)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    
    # Relationship to fetch user details
    user = db.relationship('User')


class BlacklistedToken(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    token = db.Column(db.String(500), unique=True, nullable=False)
