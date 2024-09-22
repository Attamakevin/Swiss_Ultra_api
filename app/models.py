import uuid
from datetime import datetime
from app import db, bcrypt

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
    tax_identification_number = db.Column(db.String(20), nullable=True)
    auth_code = db.Column(db.Integer, nullable=True)

    # Define relationship with Notification model
    notifications = db.relationship('Notification', backref='user', lazy=True)

    def set_password(self, password):
        self.password_hash = bcrypt.generate_password_hash(password).decode('utf-8')

    def check_password(self, password):
        return bcrypt.check_password_hash(self.password_hash, password)

    def add_notification(self, message):
        notification = Notification(message=message, user_id=self.id)
        db.session.add(notification)
        db.session.commit()


class Notification(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    message = db.Column(db.String(255), nullable=False)
    timestamp = db.Column(db.DateTime, default=datetime.utcnow)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)

