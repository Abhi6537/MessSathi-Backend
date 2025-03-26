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
        token = None

        # Extract token from Authorization header
        auth_header = request.headers.get('Authorization')
        if auth_header and auth_header.startswith("Bearer "):
            token = auth_header.split(" ")[1]  # Get only the token part

        if not token:
            return jsonify({"message": "Token is missing"}), 401

        try:
            # Decode JWT
            data = jwt.decode(token, app.config['SECRET_KEY'], algorithms=["HS256"])
            user_id = data.get("user_id")  # Ensure correct key

            if not user_id:
                return jsonify({"message": "Invalid token data"}), 401

            # Find user in database
            current_user = User.query.filter_by(id=user_id).first()
            if not current_user:
                return jsonify({"message": "User not found"}), 401

        except jwt.ExpiredSignatureError:
            return jsonify({"message": "Token has expired"}), 401
        except jwt.InvalidTokenError:
            return jsonify({"message": "Invalid token"}), 401

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
    
    # Use multi-part form data for file uploads
    data = request.form
    files = request.files
    
    # Validate required fields
    required_fields = ['title', 'description', 'address', 'locality', 'city', 'state', 'pincode', 'contact_phone']
    for field in required_fields:
        if not data.get(field):
            return jsonify({'message': f'Missing required field: {field}'}), 400
    
    try:
        # Create mess listing
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
            location=f"{data.get('location[lat]', '')},{data.get('location[lng]', '')}"
        )
        db.session.add(new_mess)
        db.session.flush()  # This will assign an ID to the mess listing
        
        # Add room details if provided
        if data.get('rooms'):
            # Assuming rooms are passed as JSON string
            import json
            rooms_data = json.loads(data['rooms'])
            for room_data in rooms_data:
                new_room = Room(
                    mess_id=new_mess.id,
                    room_type=room_data.get('type', 'single'),
                    rent=room_data.get('rent', 0),
                    capacity=room_data.get('capacity', 1),
                    available_count=room_data.get('available', 1),
                    total_count=room_data.get('total_count', 1)
                )
                db.session.add(new_room)
        
        # Handle image uploads
        if files:
            # Create upload directory if it doesn't exist
            import os
            upload_dir = 'uploads/mess_images'
            os.makedirs(upload_dir, exist_ok=True)
            
            for key, file in files.items():
                if file:
                    # Generate unique filename
                    from werkzeug.utils import secure_filename
                    import uuid
                    
                    # Secure the filename and add a unique identifier
                    filename = f"{uuid.uuid4()}_{secure_filename(file.filename)}"
                    filepath = os.path.join(upload_dir, filename)
                    
                    # Save the file
                    file.save(filepath)
                    
                    # Create MessPhoto entry
                    mess_photo = MessPhoto(
                        mess_id=new_mess.id,
                        photo_url=f"/uploads/mess_images/{filename}",
                        # Set the first image as primary if it's the first one
                        is_primary=MessPhoto.query.filter_by(mess_id=new_mess.id).count() == 0
                    )
                    db.session.add(mess_photo)
        
        db.session.commit()
        
        return jsonify({
            "message": "Mess created successfully", 
            "mess_id": new_mess.id
        }), 201
    
    except Exception as e:
        db.session.rollback()
        print(f"Error creating mess: {str(e)}")  # Log the full error
        return jsonify({
            "message": "Failed to create mess listing",
            "error": str(e)
        }), 500

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


@app.route('/api/auth/user', methods=['GET'])
@token_required
def fetch_user(current_user):
    if not current_user:
        return jsonify({'message': 'User not found'}), 404
    
    return jsonify({
        'user': {
            'name': current_user.name,
            'id': current_user.id,
            'email': current_user.email,
            'phone': current_user.phone
        }
    }), 200

@app.route('/api/messes/owner', methods=['GET'])
@token_required
def get_owner_messes(current_user):
    if current_user.user_type != UserType.OWNER:
        return jsonify({'message': 'Only owners can view their mess listings'}), 403
    
    messes = MessListing.query.filter_by(owner_id=current_user.id).all()
    result = []
    for mess in messes:
        # Get primary photo or first photo
        primary_photo = MessPhoto.query.filter_by(mess_id=mess.id, is_primary=True).first()
        if not primary_photo:
            primary_photo = MessPhoto.query.filter_by(mess_id=mess.id).first()
        
        # Get room details
        rooms = []
        for room in mess.rooms:
            rooms.append({
                'type': room.room_type,
                'price': room.rent,
                'available': room.available_count,
                'total': room.total_count
            })
        
        mess_data = {
            'id': mess.id, 
            'title': mess.title, 
            'address': mess.address,
            'status': 'active' if mess.is_active else 'draft',
            'imageUrl': primary_photo.photo_url if primary_photo else None,
            'views': 0,  # You might want to add a views tracking mechanism
            'inquiries': len(mess.inquiries),
            'rooms': rooms
        }
        result.append(mess_data)
    
    return jsonify(result)


@app.route('/api/messes/<int:id>', methods=['DELETE'])
@token_required
def delete_mess(current_user, id):
    mess = MessListing.query.filter_by(id=id, owner_id=current_user.id).first()
    
    if not mess:
        return jsonify({'message': 'Mess not found or unauthorized'}), 404

    db.session.delete(mess)
    db.session.commit()
    return jsonify({'message': 'Mess deleted successfully'})


@app.route('/uploads/<path:filename>')
def serve_uploaded_file(filename):
    from flask import send_from_directory
    return send_from_directory('uploads', filename)