from flask import Flask, request, jsonify
from flask_sqlalchemy import SQLAlchemy
from dotenv import load_dotenv
import os
from flask_cors import CORS
from app.models.models import db, users, messages, friend_requests
from werkzeug.security import generate_password_hash, check_password_hash
from sib_api_v3_sdk import SendSmtpEmail, SendSmtpEmailTo, ApiClient, TransactionalEmailsApi, Configuration
import jwt
import datetime
from datetime import timezone
from flask_socketio import SocketIO, emit, join_room


#loads the enviorment variables
load_dotenv()


#initialize the flask app and give cors support
app = Flask(__name__)
CORS(app)



#database connection details
DATABASE_URL = os.environ.get('DATABASE_URL')
app.config['SQLALCHEMY_DATABASE_URI'] = DATABASE_URL
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False

#connects sqlalchemy to flask app
db.init_app(app)


#brevo api key
API_KEY = os.environ.get('API_KEY')









#Endpoints
#############################################################################################


#endpoint to recieve sign up user data and stores it
@app.route('/api/signup/', methods=['POST'])
def createUser():
    
    try:
        data = request.get_json()
        
        user = data.get('username')
        email = data.get('email')
        password = data.get('password')
        
        #hash the password
        hashed_password = generate_password_hash(password)
        
        new_user = users(username = user, email = email, password_hash = hashed_password)
        
        db.session.add(new_user)
        print(f"User added to session: {user}")
        db.session.commit()
        print(f"Session committed successfully")
        
        
        return jsonify({"message": f'User {user} , {email}, {hashed_password} created'})
    except Exception as e:
        db.session.rollback()
        return jsonify({'error': str(e)}), 500


#endpoint to validate user login data
@app.route('/api/login/', methods=['POST'])
def checkLogin():
    
    try:
        data = request.get_json()
        
        username = data.get('username')
        password = data.get('password')
        
        
        pulledUser = users.query.filter(users.username == username).first()
        
        if pulledUser and check_password_hash(pulledUser.password_hash, password):
            
            return jsonify({'Message': 'Login Success',
                            'user': {
                            'id': pulledUser.id,
                            'username': pulledUser.username,
                            'email': pulledUser.email
                            }
                        }), 200
        
        return jsonify({'Message': 'Login Error',}), 401
        
    except Exception as e:
        return jsonify({'Message': str(e)}), 500




@app.route('/api/forgotpassword/', methods=['POST'])
def forgotPassword():
    
    try:
        data = request.get_json()
        
        email = data.get('email')
        
        if not email:
            return jsonify({'Message' : 'Invalid Email'})
            
        #check if email is in the database
        user_object = users.query.filter(users.email == email).first()
        
        if not user_object:
            return jsonify({'Message' : 'Email sent.'}), 200
        
        
        secret_key = os.environ.get('SECRET_KEY')
        if not secret_key:
            raise ValueError("SECRET_KEY not configured in environment variables")
        
        
        expire_time = datetime.datetime.now(timezone.utc) + datetime.timedelta(hours=1)
        
        expire_timestamp = expire_time.timestamp()
        
        payload = {
            'id' : user_object.id,
            'email': user_object.email,
            'exp': expire_timestamp
        }
         
        token = jwt.encode(payload, secret_key, algorithm='HS256')
        
        to = [SendSmtpEmailTo(email=email)]
        FRONTEND_URL = os.environ.get('FRONTEND_URL')
        
        send_smtp_email = SendSmtpEmail(
        to=to,
        subject="Password Reset",
        html_content=f'Click <a href=\'{FRONTEND_URL}/?token={token}\'>here</a> to reset your password.',
        sender={"name":"Whisp", "email":"yousefm2315@gmail.com"}
        )
        
        
        configuration = Configuration()
        configuration.api_key['api-key'] = API_KEY
        
        api_client = ApiClient(configuration) 
        smtp_api = TransactionalEmailsApi(api_client)
        api_response = smtp_api.send_transac_email(send_smtp_email)
        
        print(api_response)
        
        
        return jsonify({'Message' : 'Email sent.'})
        
    except Exception as e:
        return jsonify({'Message' : str(e)}), 500
    



@app.route('/api/handlereset/' , methods=['POST'])
def handleReset():
    
    data = request.get_json()
    
    token = data.get('token')
    password = data.get('password')
    confirm_password = data.get('confirmPassword')
    
    secret_key = os.environ.get('SECRET_KEY')
    
    
    token_data = jwt.decode(token, secret_key, algorithms=['HS256'])
    
    
    expire_time = token_data.get('exp')
    
    current_timestamp = datetime.datetime.now(timezone.utc).timestamp()
    
    if(current_timestamp > expire_time):
        return jsonify({'Message' : 'Link expired.'}), 400
    
    
    user = users.query.filter(users.email == token_data.get('email')).first()
    
    if not user:
        return jsonify({'Message' : 'User does not exist.'}), 401
    
    if check_password_hash(user.password_hash, password):
        return jsonify({"Message" : "Use a new password."}), 400
    
        
    user.password_hash = generate_password_hash(password)
    
    db.session.commit()
    
    return jsonify({"Message" : "Password reset successful."}), 200
    
    
@app.route('/api/getmessages/<int:user_id>/<int:contact_id>', methods=['GET'])
def getMessages(user_id, contact_id):
    
    try:
        conversation = messages.query.filter(
            db.or_(
                (messages.sender_id == user_id) & (messages.receiver_id == contact_id),
                (messages.sender_id == contact_id) & (messages.receiver_id == user_id)
            )
        ).order_by(messages.timestamp.asc()).all()
        
        messages_list = []
        for msg in conversation:
            messages_list.append({
                'id': msg.id,
                'sender_id': msg.sender_id,
                'receiver_id': msg.receiver_id,
                'content': msg.content,
                'timestamp': msg.timestamp.isoformat()
            })
            
            
        return jsonify({'messages': messages_list}), 200
    
    except Exception as e:
        return jsonify({'Message' : str(e)}), 500
    
    
    
@app.route('/api/getfriendrequests/<int:user_id>', methods=['GET'])
def getFriendRequests(user_id):
    
    requests = friend_requests.query.filter_by(receiver_id=user_id, status='pending').all()
    
    requests_list = []
    for r in requests:
        requests_list.append({
            'id': r.id,
            'sender_id': r.sender_id,
            'sender_username': users.query.get(r.sender_id).username
        })
        
    return jsonify({'requests': requests_list}), 200


@app.route('/api/getfriends/<int:user_id>', methods=['GET'])
def getFriends(user_id):
    
    friends = friend_requests.query.filter(
        db.or_(
            db.and_(friend_requests.sender_id == user_id, friend_requests.status == 'accepted'),
            db.and_(friend_requests.receiver_id == user_id, friend_requests.status == 'accepted')
        )
    ).all()
    
    friends_list = []
    for f in friends:
        friends_list.append({
            'id': f.id,
            'user_id': f.sender_id if f.sender_id != user_id else f.receiver_id,
            'username': users.query.get(f.sender_id if f.sender_id != user_id else f.receiver_id).username
        })
        
    return jsonify({'friends': friends_list}), 200




@app.route('/api/users/search', methods=['GET'])
def search_users():
    username = request.args.get('username')
    if not username:
        return jsonify({'users': []}), 400
    
    # Search for users with similar username
    found_users = users.query.filter(users.username.ilike(f'%{username}%')).all()
    
    user_list = []
    for user in found_users:
        user_list.append({
            'id': user.id,
            'username': user.username
        })
    
    return jsonify({'users': user_list})







################################################################################################




#sockets
socketio = SocketIO(app, cors_allowed_origins="*")

@socketio.on('connect')
def handle_connect():
    print('Client connected')
    
@socketio.on('join')
def handle_join(data):
    user_id = data.get('user_id')
    join_room(f'user_{user_id}')
    print(f'Client joined room: user_{user_id}')
    
    
@socketio.on('send_friend_request')
def handle_friend_request(data):
    print("Received friend request data:", data)
    
    sender_id = data.get('sender_id')
    receiver_username = data.get('receiver_username')
    
    print(f"Looking for user with username: {receiver_username}")
    receiver = users.query.filter(users.username == receiver_username).first()
    
    if not receiver:
        print(f"User '{receiver_username}' not found")
        return {'success': False, 'message': 'User not found'}
    
    print(f"Found user: ID={receiver.id}, Username={receiver.username}")
    
    # Prevent sending request to self
    if sender_id == receiver.id:
        print(f"User tried to send friend request to themselves")
        return {'success': False, 'message': 'You cannot add yourself as a friend'}
    
    # Check if there's already a pending request
    existing_request = friend_requests.query.filter_by(
        sender_id=sender_id,
        receiver_id=receiver.id,
        status='pending'
    ).first()
    
    if existing_request:
        print(f"Friend request already exists: ID={existing_request.id}")
        return {'success': False, 'message': 'Friend request already sent'}
    
    #checking for existing friendship
    existing_friendship = friend_requests.query.filter(
        db.or_(
            db.and_(
                friend_requests.sender_id == sender_id,
                friend_requests.receiver_id == receiver.id,
                friend_requests.status == 'accepted'
            ),
            db.and_(
                friend_requests.sender_id == receiver.id,
                friend_requests.receiver_id == sender_id,
                friend_requests.status == 'accepted'
            )
        )
    ).first()
    
    if existing_friendship:
        print(f"Users are already friends: Friendship ID={existing_friendship.id}")
        return {'success': False, 'message': 'You are already friends with this user'}
    
    #check if the other user already send a request
    reverse_request = friend_requests.query.filter_by(
        sender_id=receiver.id,
        receiver_id=sender_id,
        status='pending'
    ).first()
    
    if reverse_request:
        print(f"Reverse friend request exists: ID={reverse_request.id}")
        return {'success': False, 'message': 'This user has already sent you a friend request. Check your friend requests.'}
    
    new_Request = friend_requests(sender_id = sender_id,
                                  receiver_id = receiver.id,
                                  status = 'pending')
    
    db.session.add(new_Request)
    db.session.commit()
    print(f"New friend request created: ID={new_Request.id}")
    
    print(f"Emitting friend_request event to room: user_{receiver.id}")
    emit('friend_request', {
        'id': new_Request.id,
        'sender_id': sender_id,
        'sender_username': users.query.get(sender_id).username
    }, room=f'user_{receiver.id}')
    
    return {'success': True, 'message': 'Friend request sent'}
    
    
@socketio.on('accept_friend_request')
def handle_accept_friend_request(data):
    request_id = data.get('request_id')
    request = friend_requests.query.get(request_id)
    
    if request:
        request.status = 'accepted'
        db.session.commit()
        
        emit('friend_request_accepted', {
            'id': request.id,
            'user_id': request.receiver_id,
            'username': users.query.get(request.receiver_id).username
        }, room=f'user_{request.sender_id}')
        
        emit('friend_request_accepted', {
            'request_id': request_id,
            'user_id': request.sender_id,
            'username': users.query.get(request.sender_id).username
        }, room=f'user_{request.receiver_id}')
        
        return {'success': True}
    return {'success': False, 'message': 'Request not found'}

@socketio.on('reject_friend_request')
def handle_reject_friend_request(data):
    request_id = data.get('request_id')
    request = friend_requests.query.get(request_id)
    
    if request:
        db.session.delete(request)
        db.session.commit()
        return {'success': True}
    return {'success': False, 'message': 'Request not found'}
    

@socketio.on('private_message')
def handle_private_message(data):
    sender_id = data.get('sender_id')
    receiver_id = data.get('receiver_id')
    content = data.get('content')
    
    new_message = messages(sender_id = sender_id,
                           receiver_id = receiver_id,
                           content = content
                           )
    db.session.add(new_message)
    db.session.commit()
    
    
    #emit to reciever
    emit('new_message', {
        'id': new_message.id,
        'sender_id': sender_id,
        'content': content,
        'timestamp': new_message.timestamp.isoformat()
    }, room = f'user_{receiver_id}')
    
    #emit to sender
    emit('new_message', {
        'id': new_message.id,
        'sender_id': sender_id,
        'content': content,
        'timestamp': new_message.timestamp.isoformat()
    }, room = f'user_{sender_id}')
    
    return {'success': True, 'message': 'Message sent successfully'}
    
    
    
    
    
    
















if __name__ == '__main__':
    with app.app_context():
        db.create_all()
    port = int(os.environ.get("PORT", 5000))
    
    app.run(host="0.0.0.0", port=port, debug=True)
    socketio.run(app, host="0.0.0.0", port=port, debug=True)