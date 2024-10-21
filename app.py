from flask import Flask, jsonify, request, render_template, redirect, url_for, session
from pymongo import MongoClient
from werkzeug.security import generate_password_hash, check_password_hash
from flask_jwt_extended import JWTManager, create_access_token, jwt_required, get_jwt_identity
from flask_mail import Mail, Message
from bson.objectid import ObjectId
from flask_swagger_ui import get_swaggerui_blueprint
from config import Config
import secrets




app = Flask(__name__)
app.config.from_object(Config)

# MongoDB connection
client = MongoClient(app.config['MONGO_URI'])
db = client['loan_management']
users_collection = db['users']
loans_collection = db['loans'] 
admins_collection = db['admins']
jwt = JWTManager(app)
mail = Mail(app)

print(secrets.token_urlsafe(32))  
# Swagger UI setup
SWAGGER_URL = '/swagger'
API_URL = '/static/swagger.json'

swaggerui_blueprint = get_swaggerui_blueprint(
    SWAGGER_URL,
    API_URL,
    config={  # Swagger UI config options
        'app_name': "Loan Management System"
    }
)

# Register Swagger  in Flask app
app.register_blueprint(swaggerui_blueprint, url_prefix=SWAGGER_URL)

if not admins_collection.find_one({'email': 'admin@gmail.com'}):
    hashed_password = generate_password_hash('admin')
    admins_collection.insert_one({
        'email': 'admin@gmail.com',
        'password': hashed_password
    })
    print("Default admin user created.")
else:
    print("Admin user already exists.")
    
    
@app.route('/api/admin/login', methods=['POST'])
def admin_login():
    data = request.get_json()
    email = data['email']
    password = data['password']
    
    # Find the admin user
    admin = admins_collection.find_one({'email': email})
    if not admin or not check_password_hash(admin['password'], password):
        return jsonify({'msg': 'Invalid email or password'}), 401
    
    access_token = create_access_token(identity=email)
    return jsonify(access_token=access_token), 200


# Routes
@app.route('/api/register', methods=['POST'])
def register():
    data = request.get_json()
    name = data.get('name')
    email = data.get('email')
    password = data.get('password')
    contact = data.get('contact')
    address = data.get('address')
    if users_collection.find_one({'email': email}):
        return jsonify({'msg': 'User already exists'}), 409
    hashed_password = generate_password_hash(password)
    users_collection.insert_one({
        'name': name,
        'email': email,
        'password': hashed_password,
        'contact': contact,
        'address': address
    })
    
    return jsonify({'msg': 'User registered successfully'}), 201

@app.route('/api/login', methods=['POST'])
def login():
    data = request.get_json()
    email = data.get('email')
    password = data.get('password')

    user = users_collection.find_one({'email': email})

    if not user or not check_password_hash(user['password'], password):
        return jsonify({'msg': 'Invalid email or password'}), 401

    access_token = create_access_token(identity=email)
    return jsonify(access_token=access_token), 200

@app.route('/api/loans/apply', methods=['POST'])
@jwt_required()
def apply_loan():
    current_user = get_jwt_identity()
    data = request.get_json()
    if loans_collection.find_one({'email': current_user, 'purpose': data['purpose']}):
        return jsonify({'msg': 'Duplicate loan application'}), 409
    loans_collection.insert_one({
        'email': current_user,
        'amount': data['amount'],
        'tenure': data['tenure'],
        'purpose': data['purpose'],
        'status': 'Pending'
    })
    return jsonify({'msg': 'Loan application submitted successfully'}), 201

@app.route('/api/loans/status', methods=['GET'])
@jwt_required()
def loan_status():
    current_user = get_jwt_identity()
    loan = loans_collection.find_one({'email': current_user})
    if not loan:
        return jsonify({'msg': 'No loan found'}), 404
    return jsonify({
        'amount': loan['amount'],
        'tenure': loan['tenure'],
        'purpose': loan['purpose'],
        'status': loan['status']
    }), 200

@app.route('/api/admin/loans/decision', methods=['POST'])
@jwt_required()
def loan_decision():
    current_user = get_jwt_identity()
    if not admins_collection.find_one({'email': current_user}):
        return jsonify({'msg': 'Admins only'}), 403
    data = request.get_json()
    loan_id = data['loan_id']
    decision = data['decision']
    if decision not in ['approve', 'reject']:
        return jsonify({'msg': 'Invalid decision'}), 400
    result = loans_collection.update_one(
        {'_id': ObjectId(loan_id)},
        {'$set': {'status': 'Approved' if decision == 'approve' else 'Rejected'}}
    )
    if result.modified_count > 0:
        user_email = loans_collection.find_one({'_id': ObjectId(loan_id)})['email']
        send_notification(user_email, decision)
        return jsonify({'msg': 'Loan status updated successfully'}), 200
    return jsonify({'msg': 'Loan not found'}), 404

def send_notification(user_email, decision):
    status = 'approved' if decision == 'approve' else 'rejected'
    message = Message(f'Loan {status}', recipients=[user_email], body=f'Your loan has been {status}.')
    mail.send(message)
    
@app.route('/')
def index():
    return render_template('index.html')

@app.route("/admin")
def admin():
    return render_template('admin.html')

@app.route('/api/admin/login')
def admin_login_page():
    return render_template('adminlogin.html')


@app.route('/userlog')
def userlog():
    return render_template('user.html')

@app.route('/api/register')
def register_page():
    return render_template('registration.html')

@app.route('/api/loans/apply')
def applyloan():
    return render_template('applyloan.html')

@app.route('/api/login')
def login_page():
    return render_template('login.html')

@app.route('/loan-status')
@jwt_required() 
def loan_status_page():
    return render_template('viewuserstatus.html')


@app.route('/home')
def home():
    
    return render_template('home.html')

@app.route('/admin')
@jwt_required()  
def admin_dashboard():
    return render_template('admin.html')


if __name__ == '__main__':
    app.run(debug=True)
