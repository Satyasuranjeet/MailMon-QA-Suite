from flask import Flask, request, jsonify
from flask_cors import CORS
from flask_bcrypt import Bcrypt
from flask_jwt_extended import JWTManager, create_access_token, jwt_required, get_jwt_identity
from pymongo import MongoClient
from bson import ObjectId
import re
import smtplib
from email.mime.text import MIMEText
from email.mime.multipart import MIMEMultipart
from dotenv import load_dotenv
import os
import secrets

# Allow CORS for all domains


# Load environment variables
load_dotenv()

app = Flask(__name__)
CORS(app, resources={r"/*": {"origins": "*"}}, supports_credentials=True)
bcrypt = Bcrypt(app)

# Set JWT_SECRET_KEY in Flask config
app.config['JWT_SECRET_KEY'] = os.getenv("JWT_SECRET_KEY")  # Ensure this is set

jwt = JWTManager(app)

# MongoDB Connection
MONGO_URI = os.getenv("MONGO_URI")
client = MongoClient(MONGO_URI)
db = client['user_authentication']
users_collection = db['users']

# Email Configuration
SMTP_SERVER = os.getenv("SMTP_SERVER")
SMTP_PORT = int(os.getenv("SMTP_PORT"))
SENDER_EMAIL = os.getenv("SENDER_EMAIL")
SENDER_PASSWORD = os.getenv("SENDER_PASSWORD")

# Function to validate email
def validate_email(email):
    email_regex = r'^[a-zA-Z0-9._%+-]+@[a-zAZ0-9.-]+\.[a-zA-Z]{2,}$'
    return re.match(email_regex, email) is not None

# Function to send verification email
def send_verification_email(email, verification_code):
    try:
        msg = MIMEMultipart()
        msg['From'] = SENDER_EMAIL
        msg['To'] = email
        msg['Subject'] = 'Account Verification'
        
        body = f'Your verification code is: {verification_code}'
        msg.attach(MIMEText(body, 'plain'))
        
        with smtplib.SMTP(SMTP_SERVER, SMTP_PORT) as server:
            server.starttls()
            server.login(SENDER_EMAIL, SENDER_PASSWORD)
            server.send_message(msg)
        return True
    except Exception as e:
        print(f"Email sending error: {e}")
        return False

# Route for user registration
@app.route('/register', methods=['POST'])
def register():
    data = request.json
    email = data.get('email')
    password = data.get('password')
    
    # Validation
    if not email or not password:
        return jsonify({"error": "Email and password are required"}), 400
    
    if not validate_email(email):
        return jsonify({"error": "Invalid email format"}), 400
    
    if len(password) < 8:
        return jsonify({"error": "Password must be at least 8 characters"}), 400
    
    # Check if user already exists
    if users_collection.find_one({"email": email}):
        return jsonify({"error": "User already exists"}), 409
    
    # Hash password
    hashed_password = bcrypt.generate_password_hash(password).decode('utf-8')
    
    # Generate verification code
    verification_code = os.urandom(4).hex()
    
    # Create user document
    user = {
        "email": email,
        "password": hashed_password,
        "verified": False,
        "verification_code": verification_code
    }
    
    # Send verification email
    if send_verification_email(email, verification_code):
        users_collection.insert_one(user)
        return jsonify({"message": "Registration successful. Check your email for verification."}), 201
    else:
        return jsonify({"error": "Failed to send verification email"}), 500

# Route for user login
@app.route('/login', methods=['POST'])
def login():
    data = request.json
    email = data.get('email')
    password = data.get('password')
    
    user = users_collection.find_one({"email": email})
    
    if user and bcrypt.check_password_hash(user['password'], password):
        if not user.get('verified', False):
            return jsonify({"error": "Please verify your email first"}), 403
        
        # Determine user role
        user_role = 'admin' if user.get('is_admin', False) else 'user'
        
        access_token = create_access_token(identity=str(user['_id']))
        return jsonify({
            "access_token": access_token,
            "user_role": user_role
        }), 200
    
    return jsonify({"error": "Invalid credentials"}), 401

@app.route('/verify', methods=['POST'])
def verify_email():
    data = request.json
    email = data.get('email')
    verification_code = data.get('verification_code')
    
    user = users_collection.find_one({"email": email, "verification_code": verification_code})
    
    if user:
        users_collection.update_one(
            {"_id": user['_id']}, 
            {"$set": {"verified": True}, "$unset": {"verification_code": ""}}
        )
        return jsonify({"message": "Email verified successfully"}), 200
    
    return jsonify({"error": "Invalid verification code"}), 400

@app.route('/generate-api-key', methods=['POST'])
@jwt_required()
def generate_api_key():
    user_id = get_jwt_identity()

    # Check if the user already has an API key
    user = users_collection.find_one({"_id": ObjectId(user_id)})

    if user and user.get("api_key"):
        return jsonify({"message": "You already have an API key."}), 400

    # Generate a new API key
    api_key = secrets.token_hex(16)

    # Update the user's API key and usage details
    users_collection.update_one(
        {"_id": ObjectId(user_id)},
        {"$set": {
            "api_key": api_key, 
            "api_usage_limit": 1000,  # Default limit
            "current_usage": 0
        }}
    )
    return jsonify({"api_key": api_key}), 200


@app.route('/get-api-details', methods=['GET'])
@jwt_required()
def get_api_details():
    user_id = get_jwt_identity()
    user = users_collection.find_one({"_id": ObjectId(user_id)})
    
    return jsonify({
        "api_key": user.get('api_key', ''),
        "usage_limit": user.get('api_usage_limit', 0),
        "current_usage": user.get('current_usage', 0)
    }), 200


@app.route('/admin/users', methods=['GET'])
@jwt_required()
def get_all_users():
    # Check if user is admin
    user_id = get_jwt_identity()
    user = users_collection.find_one({"_id": ObjectId(user_id)})
    
    if not user.get('is_admin', False):
        return jsonify({"error": "Unauthorized"}), 403
    
    # Retrieve users and serialize ObjectId to string
    users = list(users_collection.find({}, {"password": 0}))
    for user in users:
        user['_id'] = str(user['_id'])  # Convert ObjectId to string
    
    return jsonify(users), 200

@app.route('/admin/enable-user', methods=['POST'])
@jwt_required()
def enable_user():
    user_id = get_jwt_identity()
    admin = users_collection.find_one({"_id": ObjectId(user_id)})
    
    if not admin.get('is_admin', False):
        return jsonify({"error": "Unauthorized"}), 403
    
    data = request.json
    target_user_id = data.get('user_id')
    
    users_collection.update_one(
        {"_id": ObjectId(target_user_id)},
        {"$unset": {"api_usage_disabled": ""}}
    )
    
    return jsonify({"message": "User API access enabled"}), 200

@app.route('/admin/set-user-limit', methods=['POST'])
@jwt_required()
def set_user_api_limit():
    user_id = get_jwt_identity()
    admin = users_collection.find_one({"_id": ObjectId(user_id)})
    
    if not admin.get('is_admin', False):
        return jsonify({"error": "Unauthorized"}), 403
    
    data = request.json
    target_user_id = data.get('user_id')
    new_limit = data.get('api_usage_limit')
    
    users_collection.update_one(
        {"_id": ObjectId(target_user_id)},
        {"$set": {"api_usage_limit": new_limit}}
    )
    
    return jsonify({"message": "API usage limit updated"}), 200

@app.route('/user-details', methods=['GET'])
@jwt_required()
def user_details():
    user_id = get_jwt_identity()
    user = users_collection.find_one({"_id": ObjectId(user_id)}, {"password": 0})  # Exclude password for security work

    if not user:
        return jsonify({"error": "User not found"}), 404

    return jsonify({
        "email": user.get("email"),
        "verified": user.get("verified", False),
        "api_key": user.get("api_key", None),
        "api_usage_limit": user.get("api_usage_limit", 0),
        "current_usage": user.get("current_usage", 0)
    }), 200

def validate_api_key(api_key):
    user = users_collection.find_one({"api_key": api_key})
    if user:
        return user
    return None

@app.route('/send-email', methods=['POST'])
def send_email():
    # Get API key from request headers or body
    api_key = request.args.get('apikey')
    if not api_key:
        return jsonify({"error": "API key is required"}), 400

    # Remove 'Bearer ' prefix if present
    if api_key.startswith('Bearer '):
        api_key = api_key[7:]

    # Validate API key
    user = validate_api_key(api_key)
    if not user:
        return jsonify({"error": "Invalid API key"}), 403
    
    # Check if API usage limit is reached
    if user.get('current_usage', 0) >= user.get('api_usage_limit', 1000):
        return jsonify({'error': 'API limit reached'}), 403
    if user.get('api_usage_disabled', False):
        return jsonify({'error': 'API access disabled'}), 403

    # Retrieve data from request
    data = request.json
    receiver_email = data.get('receiver_email')
    subject = data.get('subject')
    message = data.get('message')

    if not receiver_email or not subject or not message:
        return jsonify({"error": "receiver_email, subject, and message are required"}), 400

    try:
        # Create the email
        msg = MIMEMultipart()
        msg['From'] = SENDER_EMAIL
        msg['To'] = receiver_email
        msg['Subject'] = subject
        msg.attach(MIMEText(message, 'plain'))

        # Connect to the SMTP server and send the email
        with smtplib.SMTP(SMTP_SERVER, SMTP_PORT) as server:
            server.starttls()
            server.login(SENDER_EMAIL, SENDER_PASSWORD)
            server.send_message(msg)

        # Increment the user's usage count and update the database
        users_collection.update_one(
            {"_id": ObjectId(user['_id'])},
            {"$inc": {"current_usage": 1}}
        )

        return jsonify({"message": "Email sent successfully!"}), 200

    except Exception as e:
        return jsonify({"error": str(e)}), 500


@app.route('/admin/disable-user', methods=['POST'])
@jwt_required()
def disable_user():
    user_id = get_jwt_identity()
    admin = users_collection.find_one({"_id": ObjectId(user_id)})
    
    if not admin.get('is_admin', False):
        return jsonify({"error": "Unauthorized"}), 403
    
    data = request.json
    target_user_id = data.get('user_id')
    
    users_collection.update_one(
        {"_id": ObjectId(target_user_id)},
        {"$set": {"api_usage_disabled": True}}
    )
    
    return jsonify({"message": "User API access disabled"}), 200

if __name__ == '__main__':
    app.run(debug=os.getenv('FLASK_DEBUG', False))
