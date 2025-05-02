from flask_sqlalchemy import SQLAlchemy

db = SQLAlchemy()

class users(db.Model):
    __tablename__ = 'users'
    
    id = db.Column(db.Integer, primary_key = True)
    username = db.Column(db.String(50), unique = True, nullable=False)
    email = db.Column(db.String(100), unique = True, nullable = False)
    password_hash = db.Column(db.String(255), nullable = False)
    