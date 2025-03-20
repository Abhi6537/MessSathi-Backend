from flask import Flask, request, jsonify
from models import *
from flask_cors import CORS
from werkzeug.security import generate_password_hash, check_password_hash
import jwt
import datetime
from functools import wraps

app = Flask(__name__)
app.config['SQLALCHEMY_DATABASE_URI'] = "sqlite:///db.sqlite3"
app.config['SECRET_KEY'] = "YlVQB5Q5Y6LE4Jw2DFirYJqHIqkSz8ai"
app.config["SQLALCHEMY_TRACK_MODIFICATIONS"] = False
CORS(app)

db.init_app(app)

# JWT Authentication Decorator
def token_required(f):
    @wraps(f)
    def decorated(*args, **kwargs):
        token = request.headers.get('Authorization')
        if not token:
            return jsonify({'message': 'Token is missing'}), 401
        try:
            data = jwt.decode(token, app.config['SECRET_KEY'], algorithms=["HS256"])
            current_user = User.query.get(data['user_id'])
            if not current_user:
                return jsonify({'message': 'User not found'}), 401

            # Check if token is blacklisted
            if BlacklistedToken.query.filter_by(token=token).first():
                return jsonify({'message': 'Token has been revoked'}), 401

        except jwt.ExpiredSignatureError:
            return jsonify({'message': 'Token expired'}), 401
        except jwt.InvalidTokenError:
            return jsonify({'message': 'Invalid token'}), 401
        
        return f(current_user, *args, **kwargs)
    
    return decorated



@app.route('/')
def index():
    return "Mess Finder API is running!"

@app.route('/api/auth/register', methods=['POST'])
def register():
    data = request.json
    user_type = data['user_type'].upper()
    if user_type not in UserType.__members__:
        return jsonify({'error': 'Invalid user type. Choose "TENANT" or "OWNER".'}), 400
    
    hashed_password = generate_password_hash(data['password'])
    new_user = User(
        email=data['email'],
        name=data['name'],
        password_hash=hashed_password,
        phone=data.get('phone'),
        user_type=UserType[user_type]
    )
    db.session.add(new_user)
    db.session.commit()
    
    token = jwt.encode({'user_id': new_user.id, 'exp': datetime.datetime.utcnow() + datetime.timedelta(hours=24)}, 
                       app.config['SECRET_KEY'], algorithm="HS256")
    return jsonify({'message': 'User registered successfully', 'token': token})

@app.route('/api/auth/login', methods=['POST'])
def login():
    data = request.json
    user = User.query.filter_by(email=data['email']).first()
    if user and check_password_hash(user.password_hash, data['password']):
        token = jwt.encode({'user_id': user.id, 'exp': datetime.datetime.utcnow() + datetime.timedelta(hours=24)}, 
                           app.config['SECRET_KEY'], algorithm="HS256")
        return jsonify({'token': token})
    return jsonify({'message': 'Invalid credentials'}), 401

@app.route('/api/auth/logout', methods=['POST'])
@token_required
def logout(current_user):
    token = request.headers.get('Authorization')

    # Add token to blacklist
    blacklisted_token = BlacklistedToken(token=token)
    db.session.add(blacklisted_token)
    db.session.commit()

    return jsonify({'message': 'Successfully logged out'}), 200



@app.route('/api/auth/profile', methods=['GET'])
@token_required
def profile(current_user):
    return jsonify({
        'id': current_user.id,
        'email': current_user.email,
        'name': current_user.name,
        'phone': current_user.phone,
        'user_type': current_user.user_type.value
    })

@app.route('/api/messes', methods=['GET'])
def get_messes():
    messes = MessListing.query.all()
    result = [{'id': mess.id, 'title': mess.title, 'address': mess.address} for mess in messes]
    return jsonify(result)

@app.route('/api/messes', methods=['POST'])
@token_required
def create_mess(current_user):
    if current_user.user_type != UserType.OWNER:
        return jsonify({'message': 'Only owners can create mess listings'}), 403
    
    data = request.json
    new_mess = MessListing(
        owner_id=current_user.id,
        title=data['title'],
        description=data['description'],
        address=data['address'],
        locality=data['locality'],
        city=data['city'],
        state=data['state'],
        pincode=data['pincode'],
        contact_phone=data['contact_phone'],
        contact_email=data.get('contact_email'),
        location=f"{data['location']['lat']},{data['location']['lng']}"
    )
    db.session.add(new_mess)
    db.session.commit()
    return jsonify({"message": "Mess created successfully", "mess_id": new_mess.id}), 201

@app.route('/api/saved-messes', methods=['POST'])
@token_required
def save_mess(current_user):
    data = request.json
    saved_mess = SavedMess(user_id=current_user.id, mess_id=data['mess_id'])
    db.session.add(saved_mess)
    db.session.commit()
    return jsonify({'message': 'Mess saved successfully'})

@app.route('/api/saved-messes', methods=['GET'])
@token_required
def get_saved_messes(current_user):
    saved_messes = SavedMess.query.filter_by(user_id=current_user.id).all()
    result = [{'id': s.mess.id, 'title': s.mess.title} for s in saved_messes]
    return jsonify(result)

@app.route('/api/saved-messes/<int:id>', methods=['DELETE'])
@token_required
def remove_saved_mess(current_user, id):
    saved_mess = SavedMess.query.filter_by(user_id=current_user.id, mess_id=id).first()
    if not saved_mess:
        return jsonify({'message': 'Mess not found in saved list'}), 404
    db.session.delete(saved_mess)
    db.session.commit()
    return jsonify({'message': 'Mess removed from saved list'})
