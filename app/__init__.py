from flask import Flask
from flask_sqlalchemy import SQLAlchemy
from flask_migrate import Migrate
from flask_bcrypt import Bcrypt
from flask_jwt_extended import JWTManager
from flask_cors import CORS
from flask_mail import Mail
import datetime
import os


db = SQLAlchemy()
migrate = Migrate()
bcrypt = Bcrypt()
jwt = JWTManager()
mail = Mail()  
blacklist = set()

def create_app():
    app = Flask(__name__)
    app.config.from_object('app.config.Config')
    
    # Mail configuration
    app.config['MAIL_SERVER'] = 'switzultra.com'  # Your SMTP server
    app.config['MAIL_PORT'] = 465  # Port for SSL
    app.config['MAIL_USE_TLS'] = False  # Disable TLS
    app.config['MAIL_USE_SSL'] = True  # Enable SSL
    app.config['MAIL_USERNAME'] = os.environ.get('MAIL_USERNAME', 'noreply@switzultra.com')
    app.config['MAIL_PASSWORD'] = os.environ.get('MAIL_PASSWORD', 'xkHGHc9_o_[5')  # Ensure this is stored securely
    app.config['MAIL_DEFAULT_SENDER'] = 'noreply@switzultra.com'
    app.config['MAIL_MAX_EMAILS'] = None
    app.config['MAIL_ASCII_ATTACHMENTS'] = False


    # Initialize Flask-Mail with the app
    mail.init_app(app)
    

    # Initialize extensions
    db.init_app(app)
    migrate.init_app(app, db)
    bcrypt.init_app(app)
    jwt.init_app(app)
    #mail.init_app(app)  

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
