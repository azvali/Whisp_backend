from flask import Flask, request, jsonify
from flask_sqlalchemy import SQLAlchemy
from dotenv import load_dotenv
import os
from flask_cors import CORS
from app.models.users_model import db, users
from werkzeug.security import generate_password_hash, check_password_hash
from sib_api_v3_sdk import SendSmtpEmail, SendSmtpEmailTo, ApiClient, TransactionalEmailsApi, Configuration
import jwt
import datetime
from datetime import timezone


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


@app.route('/api/hello/', methods=['POST'])
def test():
    return jsonify({"message": "Backend is working!"})

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
        
        
        send_smtp_email = SendSmtpEmail(
        to=to,
        subject="Password Reset",
        html_content=f'Click <a href=\'http://localhost:5173/?token={token}\'>here</a> to reset your password.',
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
    
if __name__ == '__main__':
    with app.app_context():
        db.create_all()
    port = int(os.environ.get("PORT", 5000))
    app.run(host="0.0.0.0", port=port, debug=True)