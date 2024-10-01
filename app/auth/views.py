# backend/app/auth/views.py

from flask import Blueprint, request, jsonify,url_for
from app import db, bcrypt, mail
from app.models import User, Transfer, Notification
from flask_jwt_extended import (
    create_access_token, create_refresh_token, jwt_required, get_jwt_identity, 
    get_jwt,decode_token
)
from datetime import timedelta
from jwt.exceptions import ExpiredSignatureError, InvalidTokenError
import random
from flask_mail import Message
auth_blueprint = Blueprint('auth', __name__)

# Utility function to get current user
def get_current_user():
    try:
        current_user_identity = get_jwt_identity()
        if current_user_identity:
            return User.query.filter_by(username=current_user_identity['username']).first()
    except Exception as e:
        print(f"Error retrieving current user: {e}")
    return None

#from flask_mail import message
@auth_blueprint.route('/register', methods=['POST'])
def register():
    data = request.get_json()
    username = data.get('username')
    email = data.get('email')
    password = data.get('password')

    # Check if username is already taken
    if User.query.filter_by(username=username).first() is not None:
        return jsonify({"error": "Username already taken"}), 400

    # Check if email is already in use
    if User.query.filter_by(email=email).first() is not None:
        return jsonify({"error": "Email already in use"}), 400

    # Create a new user
    new_user = User(username=username, email=email)
    new_user.set_password(password)
    new_user.account_balance = 0.00

    # Add the new user to the database
    db.session.add(new_user)
    db.session.commit()

    # Send a welcome email with the account number
    try:
        msg = Message(
            "Welcome to SwissUltra",
            recipients=[email]
        )
        msg.body = f"""<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="UTF-8">
  <meta name="viewport" content="width=device-width, initial-scale=1.0">
  <title>Welcome Email</title>
</head>
<body style="margin: 0; padding: 0; font-family: Arial, sans-serif; background-color: #ffffff;">
  <div style="max-width: 600px; margin: 0 auto; padding: 20px; background-color: #ffffff; border-radius: 8px; box-shadow: 0 0 10px rgba(0, 0, 0, 0.1);">
    <div style="background-color: #1c3d5a; color: white; text-align: center; padding: 10px 0; font-size: 24px; font-weight: bold; border-radius: 8px 8px 0 0;">
      Welcome to [Company Name]
    </div>
    <div style="padding: 20px;">
      <p>Hi {user.user_name},</p>
      <p>Welcome to Switzultra! your account number is {new_user.account_number} We're thrilled to have you with us.</p>
      <p>Explore your dashboard and get started on [some feature or benefit of your service].</p>
      <p>If you have any questions, feel free to reach out to our support team at any time.</p>
    </div>
    <div style="text-align: center; padding: 10px; font-size: 12px; color: #777;">
      &copy; 2024 Switzultra. All rights reserved.
    </div>
  </div>
</body>
</html>"""f"Dear {username},\n\nWelcome to SwissUltra Account!\n\nYour account number is: {new_user.account_number}\n\nThank you for joining us."
        mail.send(msg)
    except Exception as e:
        return jsonify({"error": "User registered but failed to send email"}), 500

    return jsonify({"message": "User registered successfully", "account_number": new_user.account_number}), 201

@auth_blueprint.route('/login', methods=['POST'])
def login():
    data = request.get_json()
    username = data.get('username')
    password = data.get('password')

    user = User.query.filter_by(username=username).first()

    if user is None or not user.check_password(password):
        return jsonify({"error": "Invalid credentials"}), 401

    access_token = create_access_token(identity={'username': user.username}, expires_delta=timedelta(hours=1))
    refresh_token = create_refresh_token(identity={'username': user.username})

    # Return user data along with the tokens
    return jsonify({
        "access_token": access_token,
        "refresh_token": refresh_token,
        "user": {
            "username": user.username,
            "email": user.email,
            "is_admin": user.is_admin,
        }
    }), 200

#@auth_blueprint.route('/logout', methods=['POST'])
#@jwt_required()
#def logout():
 #   jti = get_jwt()['jti']
    # Store the token identifier (jti) to invalidate it later, 
    # this could be implemented with a token blacklist in production.
  #  return jsonify({"message": "Successfully logged out"}), 200

@auth_blueprint.route('/account', methods=['GET'])
@jwt_required()
def account():
    current_user = get_current_user()
    formatted_account_balance = f"{current_user.account_balance:,.2f}"
    formatted_last_credited_amount = f"{current_user.last_credited_amount:,.2f}" if current_user.last_credited_amount else None
    return jsonify({
        "username": current_user.username,
        "email": current_user.email,
        "account_number": current_user.account_number,
        "account_balance": formatted_account_balance,
        "last_credited_amount": formatted_last_credited_amount
    }), 200

@auth_blueprint.route('/admin/login', methods=['POST'])
def admin_login():
    data = request.get_json()
    username = data.get('username')
    password = data.get('password')
    
    user = User.query.filter_by(username=username, is_admin=True).first()
    
    if user is None or not user.check_password(password):
        return jsonify({"error": "Invalid credentials"}), 401
    
    access_token = create_access_token(identity={'username': user.username}, expires_delta=timedelta(hours=1))
    return jsonify({"access_token": access_token}), 200

@auth_blueprint.route('/admin/credit_user', methods=['PUT'])
@jwt_required()
def credit_user():
    current_user = get_current_user()
    if not current_user.is_admin:
        return jsonify({"error": "Unauthorized access"}), 403

    data = request.get_json()
    
    # Validate request data
    if not all([data.get('username'), data.get('account_number'), data.get('amount'), data.get('depositor_name')]):
        return jsonify({"error": "Missing required fields"}), 400

    username = data.get('username')
    account_number = data.get('account_number')
    amount = data.get('amount')
    depositor_name = data.get('depositor_name')

    # Ensure amount is a valid number
    try:
        amount = float(amount)
    except ValueError:
        return jsonify({"error": "Invalid amount"}), 400

    # Fetch user based on username or account_number
    user = User.query.filter_by(username=username, account_number=account_number).first()
    if user is None:
        return jsonify({"error": "User not found"}), 404

    # Update account balance and last credited amount
    user.account_balance += amount
    user.last_credited_amount = amount

    formatted_amount = f"{amount:,.2f}"

    # Add a notification for the user
    notification_message = f"Your account has been credited with ${formatted_amount} by {depositor_name}."
    user.add_notification(notification_message)

    db.session.commit()

    return jsonify({"message": "Account credited successfully"}), 200


@auth_blueprint.route('/admin/debit_user', methods=['PUT'])
@jwt_required()
def debit_user():
    current_user = get_current_user()
    if not current_user.is_admin:
        return jsonify({"error": "Unauthorized access"}), 403

    data = request.get_json()

    # Validate request data
    if not all([data.get('username'), data.get('account_number'), data.get('amount')]):
        return jsonify({"error": "Missing required fields"}), 400

    username = data.get('username')
    account_number = data.get('account_number')
    amount = data.get('amount')

    # Ensure amount is a valid number
    try:
        amount = float(amount)
    except ValueError:
        return jsonify({"error": "Invalid amount"}), 400

    # Fetch user based on username or account_number
    user = User.query.filter_by(username=username, account_number=account_number).first()
    if user is None:
        return jsonify({"error": "User not found"}), 404

    # Check if the user has enough funds to be debited
    if user.account_balance < amount:
        return jsonify({"error": "Insufficient funds"}), 400

    # Deduct the amount from the user's balance
    user.account_balance -= amount

    # Add a notification for the user
    notification_message = f"Your account has been debited with ${amount:.2f}."
    user.add_notification(notification_message)

    db.session.commit()

    return jsonify({"message": "Account debited successfully"}), 200

@auth_blueprint.route('/admin/edit_user', methods=['PUT'])
@jwt_required()
def edit_user():
    current_user = get_current_user()
    if not current_user.is_admin:
        return jsonify({"error": "Unauthorized access"}), 403

    data = request.get_json()
    username = data.get('username')
    new_username = data.get('new_username')
    new_email = data.get('new_email')

    user = User.query.filter_by(username=username).first()
    if user is None:
        return jsonify({"error": "User not found"}), 404

    if new_username:
        user.username = new_username
    if new_email:
        user.email = new_email

    db.session.commit()

    return jsonify({"message": "User information updated successfully"}), 200

@auth_blueprint.route('/protected', methods=['GET'])
@jwt_required()
def protected():
    current_user = get_current_user()
    return jsonify(logged_in_as=current_user.username), 200
blacklist = set()

@auth_blueprint.route('/logout', methods=['POST'])
@jwt_required()
def logout():
    jti = get_jwt()['jti']  # JWT ID
    blacklist.add(jti)  # Add the token to the blacklist
    return jsonify({"message": "Successfully logged out"}), 200

@auth_blueprint.route('/admin/register', methods=['POST'])
@jwt_required()
def register_admin():
    current_user = get_current_user()
    
    # Check if the current user is an admin
    if not current_user.is_admin:
        return jsonify({"error": "Unauthorized access"}), 403
    
    data = request.get_json()
    username = data.get('username')
    email = data.get('email')
    password = data.get('password')
    
    if User.query.filter_by(username=username).first() is not None:
        return jsonify({"error": "Username already taken"}), 400
    
    new_admin = User(username=username, email=email)
    new_admin.set_password(password)
    new_admin.is_admin = True
    new_admin.account_balance = 0.00
    
    db.session.add(new_admin)
    db.session.commit()
    
    return jsonify({"message": "Admin registered successfully"}), 201
@auth_blueprint.route('/admin/users', methods=['GET'])
@jwt_required()
def get_all_users():
    current_user = get_current_user()
    
    # Check if the current user is an admin
    if not current_user.is_admin:
        return jsonify({"error": "Unauthorized access"}), 403
    
    users = User.query.all()
    users_data = [
        {
            "username": user.username,
            "email": user.email,
            "account_number": user.account_number,
            "account_balance": user.account_balance,
            "last_credited_amount": user.last_credited_amount
        }
        for user in users
    ]
    return jsonify({"users": users_data}), 200
from datetime import datetime

@auth_blueprint.route('/notifications', methods=['GET'])
@jwt_required()
def get_notifications():
    current_user = get_jwt_identity()
    user = User.query.filter_by(username=current_user['username']).first()

    if not user:
        return jsonify({"error": "User not found"}), 404

    if not user.notifications:
        return jsonify({"notifications": []}), 200

    # Sort notifications by timestamp in descending order (newest first)
    notifications = sorted(
        [
            {
                "message": notification.message,  # Access directly
                "timestamp": notification.timestamp.isoformat() if isinstance(notification.timestamp, datetime) else str(notification.timestamp)
            }
            for notification in user.notifications
        ],
        key=lambda x: x['timestamp'], 
        reverse=True  # This makes the latest notification come first
    )

    return jsonify({"notifications": notifications}), 200

@auth_blueprint.route('/transfer', methods=['POST'])
@jwt_required()
def transfer():
    current_user = get_current_user()
    data = request.get_json()

    # Get transfer details from request
    receiver_bank = data.get('receiver_bank')
    receiver_name = data.get('receiver_name')
    receiver_account_number = data.get('receiver_account_number')
    routing_number = data.get('routing_number')
    amount = data.get('amount')

    # Check for missing fields
    if not all([receiver_name, receiver_bank, receiver_account_number, routing_number, amount]):
        return jsonify({"error": "Missing required fields"}), 400

    # Validate the amount
    try:
        amount = float(amount)
        if amount <= 0:
            return jsonify({"error": "Amount must be positive"}), 400
    except ValueError:
        return jsonify({"error": "Invalid amount format"}), 400

    # Ensure current user has sufficient balance
    if current_user.account_balance < amount:
        return jsonify({"error": "Insufficient funds"}), 400

    # Step 1: Send authentication code to user's email
    auth_code = random.randint(100, 999)
    msg = Message(
        "Transfer Authentication Code",
        recipients=[current_user.email],
        body=f"""
<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="UTF-8">
  <meta name="viewport" content="width=device-width, initial-scale=1.0">
  <title>OTP Code</title>
</head>
<body style="margin: 0; padding: 0; font-family: Arial, sans-serif; background-color: #ffffff;">
  <div style="max-width: 600px; margin: 0 auto; padding: 20px; background-color: #ffffff; border-radius: 8px; box-shadow: 0 0 10px rgba(0, 0, 0, 0.1);">
    <div style="background-color: #1c3d5a; color: white; text-align: center; padding: 10px 0; font-size: 24px; font-weight: bold; border-radius: 8px 8px 0 0;">
      Your OTP Code
    </div>
    <div style="padding: 20px; text-align: center;">
      <p>Hello,</p>
      <p>Your one-time password (OTP) is:</p>
      <p style="font-size: 24px; font-weight: bold; color: #1c3d5a; letter-spacing: 3px;">{auth_code}</p>
      <p>Please enter this code to proceed. This code is valid for the next 10 minutes.</p>
    </div>
    <div style="text-align: center; padding: 10px; font-size: 12px; color: #777;">
      If you did not request this, please ignore this email.
    </div>
  </div>
</body>
</html>
"""

    )
    mail.send(msg)

    # Create a new pending transfer
    transfer = Transfer(
        user_id=current_user.id,
        receiver_name=receiver_name,
        receiver_bank=receiver_bank,
        receiver_account_number=receiver_account_number,
        routing_number=routing_number,
        amount=amount,
        tax_verification_code=auth_code  # Save the first code here
    )
    db.session.add(transfer)
    db.session.commit()

    return jsonify({"message": "Transfer initiated. Please enter the authentication code."}), 200



@auth_blueprint.route('/verify_auth_code', methods=['POST'])
@jwt_required()
def verify_auth_code():
    current_user = get_current_user()
    data = request.get_json()

    auth_code = data.get('auth_code')

    if not auth_code:
        return jsonify({"error": "Authentication code is required"}), 400

    # Get the latest pending transfer
    transfer = Transfer.query.filter_by(user_id=current_user.id, status="pending").order_by(Transfer.created_at.desc()).first()

    if not transfer or transfer.tax_verification_code != int(auth_code):
        return jsonify({"error": "Invalid authentication code."}), 400

    # Generate a 6-digit tax verification code
    tax_verification_code = random.randint(100000, 999999)
    
    # Send the tax verification code to the user's email
    subject = "Your Tax Verification Code"
    message = f"""
<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="UTF-8">
  <meta name="viewport" content="width=device-width, initial-scale=1.0">
  <title>OTP Code</title>
</head>
<body style="margin: 0; padding: 0; font-family: Arial, sans-serif; background-color: #ffffff;">
  <div style="max-width: 600px; margin: 0 auto; padding: 20px; background-color: #ffffff; border-radius: 8px; box-shadow: 0 0 10px rgba(0, 0, 0, 0.1);">
    <div style="background-color: #1c3d5a; color: white; text-align: center; padding: 10px 0; font-size: 24px; font-weight: bold; border-radius: 8px 8px 0 0;">
      Your OTP Code
    </div>
    <div style="padding: 20px; text-align: center;">
      <p>Hello,</p>
      <p>Your one-time password (OTP) is:</p>
      <p style="font-size: 24px; font-weight: bold; color: #1c3d5a; letter-spacing: 3px;">{tax_verification_code}</p>
      <p>Please enter this code to proceed. This code is valid for the next 10 minutes.</p>
    </div>
    <div style="text-align: center; padding: 10px; font-size: 12px; color: #777;">
      If you did not request this, please ignore this email.
    </div>
  </div>
</body>
</html>
"""

    send_email(current_user.email, subject, message)

    # Save the tax verification code
    transfer.tax_verification_code = tax_verification_code
    db.session.commit()

    return jsonify({"message": "Authentication code verified. Tax verification code sent."}), 200

import random
from flask import jsonify, request
from flask_jwt_extended import jwt_required

@auth_blueprint.route('/save_tin', methods=['POST'])
@jwt_required()
def save_tin():
    current_user = get_current_user()
    data = request.get_json()

    tax_verification_code = data.get('tax_verification_code')

    if not tax_verification_code:
        return jsonify({"error": "Tax verification code is required"}), 400

    # Get the latest pending transfer
    transfer = Transfer.query.filter_by(user_id=current_user.id, status="pending").order_by(Transfer.created_at.desc()).first()

    if not transfer or transfer.tax_verification_code != int(tax_verification_code):
        return jsonify({"error": "Invalid tax verification code."}), 400

    # Generate a 4-digit final authentication code
    final_auth_code = random.randint(1000, 9999)

    # Send the final authentication code to the user's email
    subject = "Final Authentication Code"
    message = f"""<!DOCTYPE html>

<html lang="en">
<head>
  <meta charset="UTF-8">
  <meta name="viewport" content="width=device-width, initial-scale=1.0">
  <title>OTP Code</title>
</head>
<body style="margin: 0; padding: 0; font-family: Arial, sans-serif; background-color: #ffffff;">
  <div style="max-width: 600px; margin: 0 auto; padding: 20px; background-color: #ffffff; border-radius: 8px; box-shadow: 0 0 10px rgba(0, 0, 0, 0.1);">
    <div style="background-color: #1c3d5a; color: white; text-align: center; padding: 10px 0; font-size: 24px; font-weight: bold; border-radius: 8px 8px 0 0;">
      Your OTP Code
    </div>
    <div style="padding: 20px; text-align: center;">
      <p>Hello,</p>
      <p>Your one-time password (OTP) is:</p>
      <p style="font-size: 24px; font-weight: bold; color: #1c3d5a; letter-spacing: 3px;">{final_auth_code}</p>
      <p>Please enter this code to proceed. This code is valid for the next 10 minutes.</p>
    </div>
    <div style="text-align: center; padding: 10px; font-size: 12px; color: #777;">
      If you did not request this, please ignore this email.
    </div>
  </div>
</body>
</html>"""
    #message = f"Your final authentication code is: {final_auth_code}"
    send_email(current_user.email, subject, message)

    # Save the final authentication code
    transfer.final_auth_code = final_auth_code
    db.session.commit()

    return jsonify({"message": "Tax verification code saved successfully. Final authentication code sent."}), 200



@auth_blueprint.route('/complete_transfer', methods=['POST'])
@jwt_required()
def complete_transfer():
    current_user = get_current_user()
    data = request.get_json()

    final_auth_code = data.get('final_auth_code')

    if not final_auth_code:
        return jsonify({"error": "Final authentication code is required"}), 400

    # Get the latest pending transfer
    transfer = Transfer.query.filter_by(user_id=current_user.id, status="pending").order_by(Transfer.created_at.desc()).first()

    if not transfer or transfer.final_auth_code != int(final_auth_code):
        return jsonify({"error": "Invalid final authentication code."}), 400

    # Deduct the amount from the user's account balance
    current_user.account_balance -= transfer.amount

    # Mark transfer as completed
    transfer.status = "completed"
    db.session.commit()

    formatted_amount = f"{transfer.amount:,.2f}"
    notification_message = (
        f"Transfer of ${formatted_amount} to {transfer.receiver_name} "
        f"(Account: {transfer.receiver_account_number}, Bank: {transfer.receiver_bank}) "
        "has been successfully processed. You will receive the value in your bank account within 4-7 days."
    )
    
    # Add notification to the user about the transfer
    current_user.add_notification(notification_message)

    return jsonify({"message": "Transfer successful. You will receive the value in your bank account within 4-7 days."}), 200
# Forgot Password Request
@auth_blueprint.route('/forgot_password', methods=['POST'])
def forgot_password():
    data = request.get_json()
    email = data.get('email')

    # Validate the email
    if not email:
        return jsonify({"error": "Email is required"}), 400

    # Search for the user in the database
    user = User.query.filter_by(email=email).first()

    # Even if user is not found, return the same response to prevent email enumeration
    if user:
        # Generate a unique token for password reset
        token = create_reset_token(user.id)

        # Create the password reset URL
        reset_url = f"https://banking-dashboard-navy.vercel.app/reset-password?token={token}"

        # Prepare the email content
        subject = "Password Reset Request"
        message = f"""<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="UTF-8">
  <meta name="viewport" content="width=device-width, initial-scale=1.0">
  <title>Password Reset</title>
</head>
<body style="margin: 0; padding: 0; font-family: Arial, sans-serif; background-color: #ffffff;">
  <div style="max-width: 600px; margin: 0 auto; padding: 20px; background-color: #ffffff; border-radius: 8px; box-shadow: 0 0 10px rgba(0, 0, 0, 0.1);">
    <div style="background-color: #1c3d5a; color: white; text-align: center; padding: 10px 0; font-size: 24px; font-weight: bold; border-radius: 8px 8px 0 0;">
      Password Reset Request
    </div>
    <div style="padding: 20px;">
      <p>Dear {user.username},</p>
      <p>We received a request to reset your password. Click the button below to reset your password:</p>
      <div style="text-align: center; margin: 20px;">
        <a href=" {reset_url}" style="background-color: #1c3d5a; color: white; padding: 10px 20px; text-decoration: none; border-radius: 5px;">Reset Password</a>
      </div>
      <p>If you didn't request this, you can safely ignore this email.</p>
    </div>
    <div style="text-align: center; padding: 10px; font-size: 12px; color: #777;">
      &copy; 2024 Company. All rights reserved.
    </div>
  </div>
</body>
</html>"""#f"""
        #Hi {user.username},

        #We received a request to reset your password. You can reset your password by clicking the link below:
        
        #{reset_url}

        #If you did not request a password reset, please ignore this email or contact support if you have any questions.

        #Thanks,
        #Your Team
        #"""

        # Send the email with the reset link
        send_email(user.email, subject, message)

    # Return success message to prevent email enumeration
    return jsonify({"message": "If your email is registered, a reset link will be sent."}), 200

# Reset Password
@auth_blueprint.route('/reset_password/<token>', methods=['POST'])
def reset_password(token):
    try:
        # Decode the reset token to get the user's ID
        user_id = decode_reset_token(token)
    except Exception as e:
        return jsonify({"error": "Invalid or expired token"}), 400

    # Get the new password from the request
    data = request.get_json()
    new_password = data.get('new_password')

    if not new_password:
        return jsonify({"error": "Password is required"}), 400

    # Get the user by ID
    user = User.query.get(user_id)

    if not user:
        return jsonify({"error": "User not found"}), 404

    # Update the user's password (hash it before saving)
    from werkzeug.security import generate_password_hash

    user.set_password(new_password)
    db.session.commit()

    return jsonify({"message": "Password reset successful"}), 200

# Helper function to create reset token (valid for 1 hour)
def create_reset_token(user_id):
    expires = timedelta(hours=1)  # Token valid for 1 hour
    return create_access_token(identity=user_id, expires_delta=expires)

# Helper function to decode the reset token
def decode_reset_token(token):
    try:
        decoded_token = decode_token(token)
        user_id = decoded_token['sub']  # 'sub' is the user_id
        return user_id
    except (ExpiredSignatureError, InvalidTokenError):
        raise Exception("Invalid or expired token")

# Helper function to send emails
def send_email(recipient, subject, html_message):
    msg = Message(subject, recipients=[recipient])
    msg.html = html_message  # Set the HTML content here
    mail.send(msg)

@auth_blueprint.route('/send_message', methods=['POST'])
def send_message():
    data = request.get_json()

    # Validate the incoming data
    name = data.get('name')
    email = data.get('email')
    subject = data.get('subject')
    message = data.get('message')

    if not all([name, email, subject, message]):
        return jsonify({"error": "All fields are required"}), 400

    # Compose the message
    email_subject = f"New message from {name}: {subject}"
    email_body = f"""
    You have received a new message from {name} ({email}):

    Subject: {subject}

    Message:
    {message}
    """

    # Send email to support
    try:
        msg = Message(subject=email_subject,
                      recipients=["support@switzultra.com"],
                      body=email_body)

        mail.send(msg)
        return jsonify({"message": "Message sent successfully"}), 200

    except Exception as e:
        return jsonify({"error": f"Failed to send message: {str(e)}"}), 500
