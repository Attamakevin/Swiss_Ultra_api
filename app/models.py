import uuid
from datetime import datetime
from app import db, bcrypt
from sqlalchemy.dialects.postgresql import JSON
class User(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(150), unique=True, nullable=False)
    email = db.Column(db.String(150), unique=True, nullable=False)
    password_hash = db.Column(db.String(128), nullable=False)
    account_number = db.Column(db.String(10), unique=True, nullable=False, default=lambda: str(uuid.uuid4().int)[:10])
    is_admin = db.Column(db.Boolean, default=False)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    account_balance = db.Column(db.Float, default=0.00)
    last_credited_amount = db.Column(db.Float, default=0.00)
    tax_identification_number = db.Column(db.String(20), nullable=True)  # Optional TIN storage
    transfers = db.relationship('Transfer', backref='user', lazy=True)
    notifications = db.relationship('Notification', backref='user_notifications', lazy=True)  # Change backref name

    def set_password(self, password):
        """Hash the password and store it in the password_hash field."""
        self.password_hash = bcrypt.generate_password_hash(password).decode('utf-8')

    def check_password(self, password):
        """Check the provided password against the stored password hash."""
        return bcrypt.check_password_hash(self.password_hash, password)


class TransactionLog(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)  # Link to user
    type = db.Column(db.String(20), nullable=False)  # Deposit, Withdrawal, Transfer
    amount = db.Column(db.Float, nullable=False)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    description = db.Column(db.String(250), nullable=True)  # Optional description for transaction

class Transfer(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'))
    notifications = db.relationship('Notification', backref='transfer', lazy=True)  # Keeping this for transfer notifications
    receiver_name = db.Column(db.String(150), nullable=False)
    receiver_bank = db.Column(db.String(150), nullable=False)
    receiver_account_number = db.Column(db.String(20), nullable=False)
    routing_number = db.Column(db.String(20), nullable=False)
    amount = db.Column(db.Float, nullable=False)
    status = db.Column(db.String(20), default="pending")  # Status: pending, completed, failed
    tax_verification_code = db.Column(db.Integer, nullable=True)
    final_auth_code = db.Column(db.Integer, nullable=True)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    updated_at = db.Column(db.DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)

    def add_notification(self, message):
        notification = Notification(message=message, user_id=self.user_id)  # Use user_id for the sender
        db.session.add(notification)
        db.session.commit()



class Notification(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    message = db.Column(db.String(255), nullable=False)
    timestamp = db.Column(db.DateTime, default=datetime.utcnow)
    transfer_id = db.Column(db.Integer, db.ForeignKey('transfer.id'))
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    user = db.relationship('User', backref='notifications-list', lazy=True)  # Keep this as is
