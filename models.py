# models.py

from flask_sqlalchemy import SQLAlchemy
from flask_login import UserMixin
from werkzeug.security import generate_password_hash, check_password_hash

db = SQLAlchemy()

class User(db.Model, UserMixin):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(150), unique=True, nullable=False)
    password = db.Column(db.String(150), nullable=False)
    role = db.Column(db.String(50), nullable=False)  # admin, vender_machine, student

    def set_password(self, password):
        self.password = generate_password_hash(password)

    def check_password(self, password):
        return check_password_hash(self.password, password)

class FileUpload(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    filename = db.Column(db.String(150), nullable=False)
    description = db.Column(db.String(250))
    upload_time = db.Column(db.DateTime, nullable=False)
    vender_machine_id = db.Column(db.Integer, db.ForeignKey('user.id'))

    vender_machine = db.relationship('User', backref='uploads')
class Transaction(Base):
    __tablename__ = 'transaction'
    id = Column(Integer, primary_key=True)
    user_id = Column(Integer, ForeignKey('user.id'))
    amount = Column(Float)
    transaction_type = Column(String)
    card_number = Column(String)  # Ensure this field is defined
    timestamp = Column(DateTime, default=datetime.utcnow)
