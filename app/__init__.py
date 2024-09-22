from flask import Flask
from flask_sqlalchemy import SQLAlchemy
from flask_migrate import Migrate
from flask_bcrypt import Bcrypt
from flask_jwt_extended import JWTManager
from flask_cors import CORS
from flask_mail import Mail
import datetime

db = SQLAlchemy()
migrate = Migrate()
bcrypt = Bcrypt()
jwt = JWTManager()
mail = Mail()  
blacklist = set()

def create_app():
    app = Flask(__name__)
    app.config.from_object('app.config.Config')
    #mail configuration
    MAIL_SERVER = 'smtp.switzultra.com'  # e.g., smtp.gmail.com or any other SMTP service provider
    MAIL_PORT = 587  # or 465 if using SSL
    MAIL_USE_TLS = True  # Use TLS for security
    MAIL_USE_SSL = False  # Use SSL (if required by your mail provider)
    MAIL_USERNAME = 'noreply@switzultra.com'  # Your admin email address
    MAIL_PASSWORD = 'xkHGHc9_o_[5'  # Password for the email account
    MAIL_DEFAULT_SENDER = 'noreply@switzultra.com'  # Default sender email address for outgoing emails
    MAIL_MAX_EMAILS = None
    MAIL_ASCII_ATTACHMENTS = False

    # Initialize extensions
    db.init_app(app)
    migrate.init_app(app, db)
    bcrypt.init_app(app)
    jwt.init_app(app)
    mail.init_app(app)  

    # Register blueprints
    from app.auth.views import auth_blueprint
    app.register_blueprint(auth_blueprint, url_prefix='/auth')

    # Enable CORS for the entire application
    CORS(app, resources={r"/*": {"origins": "*"}})

    # JWT token blacklist checking
    @jwt.token_in_blocklist_loader
    def check_if_token_is_revoked(jwt_header, jwt_payload):
        jti = jwt_payload['jti']
        return jti in blacklist

    return app
