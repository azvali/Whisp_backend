from flask_sqlalchemy import SQLAlchemy
import datetime

db = SQLAlchemy()

class users(db.Model):
    __tablename__ = 'users'
    
    id = db.Column(db.Integer, primary_key = True)
    username = db.Column(db.String(50), unique = True, nullable=False)
    email = db.Column(db.String(100), unique = True, nullable = False)
    password_hash = db.Column(db.String(255), nullable = False)
    
    
class messages(db.Model):
    __tablename__ = 'messages'
    
    id = db.Column(db.Integer, primary_key = True)
    sender_id = db.Column(db.Integer, db.ForeignKey('users.id'), nullable = False)
    receiver_id = db.Column(db.Integer, db.ForeignKey('users.id'), nullable = False)
    content = db.Column(db.String(255), nullable = False)
    timestamp = db.Column(db.DateTime, default = datetime.datetime.now(datetime.timezone.utc))
    
    sender = db.relationship('users', foreign_keys = [sender_id], backref='sent_messages')
    receiver = db.relationship('users', foreign_keys = [receiver_id], backref='received_messages')

class friend_requests(db.Model):
    __tablename__ = 'friend_requests'
    
    id = db.Column(db.Integer, primary_key = True)
    sender_id = db.Column(db.Integer, db.ForeignKey('users.id'), nullable = False)
    receiver_id = db.Column(db.Integer, db.ForeignKey('users.id'), nullable = False)
    status = db.Column(db.String(20), default = 'pending')

    sender = db.relationship('users', foreign_keys = [sender_id], backref='sent_requests')
    receiver = db.relationship('users', foreign_keys = [receiver_id], backref='received_requests')
