import bcrypt
from flask_sqlalchemy import SQLAlchemy
from flask_login import UserMixin
from werkzeug.security import generate_password_hash, check_password_hash
from app import db# Ensure the import matches the app structure
from flask_bcrypt import Bcrypt
import logging
from datetime import datetime

logger = logging.getLogger(__name__)

bcrypt = Bcrypt()


class Order(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    item_name = db.Column(db.String(150), nullable=False)
    quantity = db.Column(db.Integer, nullable=False)
    price = db.Column(db.Float, nullable=False)
    address = db.Column(db.String(250), nullable=True)
    mobile = db.Column(db.String(50), nullable=True)
    payment_method = db.Column(db.String(50), nullable=True)

    __tablename__ = 'order'
    __table_args__ = {'extend_existing': True}

class User(db.Model, UserMixin):
    id = db.Column(db.Integer, primary_key=True)
    email = db.Column(db.String(150), unique=True, nullable=False)
    name = db.Column(db.String(150), nullable=False)
    phone = db.Column(db.String(50), nullable=False)
    password_hash = db.Column(db.String(150), nullable=False)
    is_admin = db.Column(db.Boolean, default=False)

    __tablename__ = 'user'
    __table_args__ = {'extend_existing': True}  # Allow extending the existing table

    def __repr__(self):
        return f"User('{self.email}', '{self.name}', '{self.phone}', '{self.is_admin}')"

    def set_password(self, password):
        logger.debug("Setting password for user: %s", self.email)
        self.password_hash = bcrypt.generate_password_hash(password).decode('utf-8')
        logger.debug("Password hash set: %s", self.password_hash)

    def check_password(self, password):
        logger.debug("Checking password for user: %s", self.email)
        is_valid = bcrypt.check_password_hash(self.password_hash, password)
        logger.debug("Password check result: %s", is_valid)
        return is_valid
class Booking(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    name = db.Column(db.String(100), nullable=False)
    email = db.Column(db.String(120), nullable=False)
    phone = db.Column(db.String(20), nullable=False)
    date = db.Column(db.DateTime, nullable=False, default=datetime.utcnow)
    special_request = db.Column(db.Text, nullable=True)

    def __repr__(self):
        return f'<Booking {self.name}>'    
