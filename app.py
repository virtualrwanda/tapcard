from flask import Flask, render_template, redirect, url_for, flash, request, session, jsonify
from flask_sqlalchemy import SQLAlchemy
from flask_wtf import FlaskForm
from wtforms import StringField, PasswordField, SelectField, SubmitField, FloatField
from wtforms.validators import DataRequired, Length, Email, Regexp
from werkzeug.security import generate_password_hash, check_password_hash
import os
from datetime import datetime, date, timedelta
from functools import wraps
from sqlalchemy import func
from flask_wtf.csrf import CSRFProtect
from flask_mail import Mail, Message
import joblib
import numpy as np
import pandas as pd
from sqlalchemy.sql import text
from dotenv import load_dotenv
import logging

# Load environment variables
load_dotenv()

# Configure logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

app = Flask(__name__)
csrf = CSRFProtect(app)
app.config['SECRET_KEY'] = os.getenv('SECRET_KEY', 'your_secret_key')
app.config['SQLALCHEMY_DATABASE_URI'] = os.getenv('DATABASE_URI', 'sqlite:///site.db')
app.config['UPLOAD_FOLDER'] = 'static/uploads'
app.config['SESSION_COOKIE_SECURE'] = True  # Secure sessions in production
os.makedirs(app.config['UPLOAD_FOLDER'], exist_ok=True)
db = SQLAlchemy(app)

# Mail configuration
app.config['MAIL_SERVER'] = os.getenv('MAIL_SERVER', 'mail.vrt.rw')
app.config['MAIL_PORT'] = int(os.getenv('MAIL_PORT', 587))
app.config['MAIL_USE_TLS'] = os.getenv('MAIL_USE_TLS', 'True') == 'True'
app.config['MAIL_USERNAME'] = os.getenv('MAIL_USERNAME')
app.config['MAIL_PASSWORD'] = os.getenv('MAIL_PASSWORD')
mail = Mail(app)

roles = [('admin', 'Admin'), ('vender_machine', 'Vender Machine'), ('client', 'Client')]
model = joblib.load('arima_model.pkl')

# Models
class User(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(25), unique=True, nullable=False)
    email = db.Column(db.String(120), unique=True, nullable=False)
    password = db.Column(db.String(60), nullable=False)
    role = db.Column(db.String(10), nullable=False)

    def __repr__(self):
        return f"User('{self.username}', '{self.role}')"

class Transfer(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    sender_card_number = db.Column(db.String(20), nullable=False)
    receiver_card_number = db.Column(db.String(20), nullable=False)
    amount = db.Column(db.Float, nullable=False)
    date = db.Column(db.DateTime, default=datetime.utcnow)

    def __repr__(self):
        return f"<Transfer {self.sender_card_number} to {self.receiver_card_number} - {self.amount}>"

class FileUpload(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    filename = db.Column(db.String(100), nullable=False)
    description = db.Column(db.String(200), nullable=False)
    username = db.Column(db.String(25), db.ForeignKey('user.username'), nullable=False)

    def __repr__(self):
        return f"FileUpload('{self.filename}', '{self.description}', '{self.username}')"

class Card(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    card_number = db.Column(db.String(20), nullable=False, unique=True)
    cardholder_name = db.Column(db.String(100), nullable=False)
    balance = db.Column(db.Float, default=0.0)
    expiry_date = db.Column(db.Date, nullable=False, default=lambda: date.today() + timedelta(days=3*365))
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)

    def __repr__(self):
        return f"Card('{self.card_number}', '{self.cardholder_name}', '{self.balance}')"

class Transaction(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    amount = db.Column(db.Float, nullable=False)
    transaction_type = db.Column(db.String(50), nullable=False)
    card_number = db.Column(db.String(20), nullable=False)
    timestamp = db.Column(db.DateTime, default=datetime.utcnow)

    def __repr__(self):
        return f"Transaction('{self.amount}', '{self.transaction_type}', '{self.timestamp}')"

# Forms
class RegistrationForm(FlaskForm):
    username = StringField('Username', validators=[DataRequired(), Length(min=3, max=25)])
    email = StringField('Email', validators=[DataRequired(), Email()])
    password = PasswordField('Password', validators=[DataRequired(), Length(min=6, max=25)])
    role = SelectField('Role', choices=roles, validators=[DataRequired()])
    submit = SubmitField('Register')

class LoginForm(FlaskForm):
    username = StringField('Username', validators=[DataRequired()])
    password = PasswordField('Password', validators=[DataRequired()])
    submit = SubmitField('Login')

class UploadForm(FlaskForm):
    file = StringField('Upload PDF File', validators=[DataRequired()])
    description = StringField('Description', validators=[DataRequired()])
    submit = SubmitField('Upload')

class CardForm(FlaskForm):
    card_number = StringField('Card Number', validators=[
        DataRequired(),
        Regexp(r'^\d{16}$', message='Card number must be 16 digits')
    ])
    cardholder_name = StringField('Cardholder Name', validators=[DataRequired()])
    submit = SubmitField('Add Card')

class TransactionForm(FlaskForm):
    card_number = StringField('Card Number', validators=[DataRequired()])
    amount = FloatField('Amount', validators=[DataRequired()])
    transaction_type = SelectField('Transaction Type', choices=[
        ('topup', 'Top Up'), ('purchase', 'Purchase'), ('transfer', 'Transfer')
    ], validators=[DataRequired()])
    submit = SubmitField('Submit')

class TransferForm(FlaskForm):
    sender_card_number = StringField('Sender Card Number', validators=[DataRequired()])
    receiver_card_number = StringField('Receiver Card Number', validators=[DataRequired()])
    amount = FloatField('Amount', validators=[DataRequired()])
    submit = SubmitField('Transfer')

class TransformOneCard(FlaskForm):
    card_number = StringField('Card Number', validators=[DataRequired()])
    card_receiver = StringField('Card Receiver', validators=[DataRequired()])
    amount = FloatField('Amount', validators=[DataRequired()])
    transaction_type = SelectField(
        'Transaction Type',
        choices=[('transfer', 'Transfer'), ('withdraw', 'Withdraw'), ('deposit', 'Deposit')],
        validators=[DataRequired()]
    )
    submit = SubmitField('Submit')

class EmailRequestForm(FlaskForm):
    recipient_email = StringField('Recipient Email', validators=[DataRequired(), Email()])
    submit = SubmitField('Request Report')

# Role decorator
def role_required(role):
    def wrapper(fn):
        @wraps(fn)
        def decorated_view(*args, **kwargs):
            if 'username' not in session or session['role'] != role:
                flash('You do not have permission to access this page.', 'danger')
                return redirect(url_for('home'))
            return fn(*args, **kwargs)
        return decorated_view
    return wrapper

# Email sending function
def send_user_report(user_id, recipient_email):
    with app.app_context():
        user = User.query.get(user_id)
        if not user:
            logger.error(f"User {user_id} not found.")
            return "User not found"

        cards = Card.query.filter_by(user_id=user.id).all()
        transactions = Transaction.query.filter_by(user_id=user.id).all()
        files = FileUpload.query.filter_by(username=user.username).all()

        message_body = f"A NOVEL AI_IoT BASED TAP AND GO CARD SYSTEM\n\n"
        message_body += f"User Report for {user.username}:\n"
        message_body += f"Username: {user.username}\n"
        message_body += f"Email: {user.email}\n"
        message_body += f"Role: {user.role}\n\n"

        message_body += "Cards:\n"
        if cards:
            for card in cards:
                message_body += f"  Card Number: {card.card_number}\n"
                message_body += f"  Cardholder Name: {card.cardholder_name}\n"
                message_body += f"  Balance: {card.balance}\n"
                message_body += f"  Expiry Date: {card.expiry_date}\n\n"
        else:
            message_body += "  No cards registered.\n\n"

        message_body += "Transactions:\n"
        if transactions:
            for transaction in transactions:
                message_body += f"  Amount: {transaction.amount}\n"
                message_body += f"  Type: {transaction.transaction_type}\n"
                message_body += f"  Card Number: {transaction.card_number}\n"
                message_body += f"  Timestamp: {transaction.timestamp}\n\n"
        else:
            message_body += "  No transactions recorded.\n\n"

        message_body += "Uploaded Files:\n"
        if files:
            for file in files:
                message_body += f"  Filename: {file.filename}\n"
                message_body += f"  Description: {file.description}\n\n"
        else:
            message_body += "  No files uploaded.\n\n"

        msg = Message("User Report - Tap and Go Card System",
                      sender=app.config['MAIL_USERNAME'],
                      recipients=[recipient_email])
        msg.body = message_body

        try:
            mail.send(msg)
            logger.info(f"Email sent successfully to {recipient_email} for user {user_id}")
            return "Email sent successfully"
        except Exception as e:
            logger.error(f"Error sending email to {recipient_email}: {e}")
            return f"Error sending email: {e}"

# Routes
@app.route('/')
def home():
    return render_template('homepage.html')

@app.route('/register', methods=['GET', 'POST'])
def register():
    form = RegistrationForm()
    if form.validate_on_submit():
        hashed_password = generate_password_hash(form.password.data, method='pbkdf2:sha256')
        user = User(
            username=form.username.data,
            email=form.email.data,
            password=hashed_password,
            role=form.role.data
        )
        try:
            db.session.add(user)
            db.session.commit()
            flash('Registration successful! You can now log in.', 'success')
            return redirect(url_for('login'))
        except Exception as e:
            db.session.rollback()
            logger.error(f"Registration error: {e}")
            flash('Registration failed. Username or email may already exist.', 'danger')
    return render_template('register.html', form=form)

@app.route('/login', methods=['GET', 'POST'])
def login():
    form = LoginForm()
    if form.validate_on_submit():
        user = User.query.filter_by(username=form.username.data).first()
        if user and check_password_hash(user.password, form.password.data):
            session['username'] = user.username
            session['role'] = user.role
            session['user_id'] = user.id
            flash('Login successful!', 'success')
            return redirect(url_for('dashboard'))
        else:
            flash('Login failed. Check your username and password.', 'danger')
    return render_template('login.html', form=form)

@app.route('/dashboard')
def dashboard():
    if 'username' not in session:
        return redirect(url_for('login'))
    role = session['role']
    if role == 'admin':
        return redirect(url_for('admin_dashboard'))
    elif role == 'client':
        return redirect(url_for('client_dashboard'))
    elif role == 'vender_machine':
        return redirect(url_for('vender_machine_dashboard'))
    flash('Role not recognized', 'danger')
    return redirect(url_for('home'))

@app.route('/admin_dashboard')
@role_required('admin')
def admin_dashboard():
    try:
        users = User.query.all()
        uploads = FileUpload.query.all()
        transactions = Transaction.query.order_by(Transaction.timestamp.desc()).limit(10).all()
        total_users = User.query.count()
        total_uploads = FileUpload.query.count()
        total_transactions = Transaction.query.count()
        user_roles_count = db.session.query(User.role, func.count(User.id)).group_by(User.role).all()
        transactions_by_type = db.session.query(Transaction.transaction_type, func.sum(Transaction.amount)).group_by(Transaction.transaction_type).all()
        roles_data = {role: count for role, count in user_roles_count} if user_roles_count else {"No Data": 0}
        transactions_data = {t_type: amount for t_type, amount in transactions_by_type} if transactions_by_type else {"No Data": 0}
        return render_template(
            'admin_dashboard.html',
            username=session['username'],
            users=users,
            uploads=uploads,
            transactions=transactions,
            total_users=total_users,
            total_uploads=total_uploads,
            total_transactions=total_transactions,
            roles_data=roles_data,
            transactions_data=transactions_data
        )
    except Exception as e:
        logger.error(f"Error loading admin dashboard: {e}")
        flash('An error occurred while loading the dashboard.', 'danger')
        return redirect(url_for('home'))

@app.route('/client_dashboard')
@role_required('client')
def client_dashboard():
    username = session['username']
    search_query = request.args.get('search', '').lower()
    vender_machine_uploads = db.session.query(FileUpload, User).join(User).filter(
        User.role == 'vender_machine',
        (FileUpload.filename.ilike(f"%{search_query}%") | FileUpload.description.ilike(f"%{search_query}%"))
    ).all()
    uploads = [
        {'filename': upload.filename, 'description': upload.description, 'username': user.username}
        for upload, user in vender_machine_uploads
    ]
    return render_template('client_dashboard.html', username=username, uploads=uploads)

@app.route('/vender_machine_dashboard')
@role_required('vender_machine')
def vender_machine_dashboard():
    username = session['username']
    user_uploads = FileUpload.query.filter_by(username=username).all()
    return render_template('vender_machine_dashboard.html', username=username, uploads=user_uploads)

@app.route('/create_user', methods=['GET', 'POST'])
@role_required('admin')
def create_user():
    form = RegistrationForm()
    if form.validate_on_submit():
        hashed_password = generate_password_hash(form.password.data, method='pbkdf2:sha256')
        user = User(
            username=form.username.data,
            email=form.email.data,
            password=hashed_password,
            role=form.role.data
        )
        try:
            db.session.add(user)
            db.session.commit()
            flash('User created successfully!', 'success')
            return redirect(url_for('admin_dashboard'))
        except Exception as e:
            db.session.rollback()
            logger.error(f"Create user error: {e}")
            flash('Failed to create user. Username or email may already exist.', 'danger')
    return render_template('register.html', form=form)

@app.route('/edit_user/<username>', methods=['GET', 'POST'])
@role_required('admin')
def edit_user(username):
    user = User.query.filter_by(username=username).first()
    if not user:
        flash('User not found', 'danger')
        return redirect(url_for('admin_dashboard'))
    form = RegistrationForm()
    if form.validate_on_submit():
        user.username = form.username.data
        user.email = form.email.data
        user.role = form.role.data
        if form.password.data:
            user.password = generate_password_hash(form.password.data, method='pbkdf2:sha256')
        try:
            db.session.commit()
            flash('User updated successfully!', 'success')
            return redirect(url_for('admin_dashboard'))
        except Exception as e:
            db.session.rollback()
            logger.error(f"Edit user error: {e}")
            flash('Failed to update user. Username or email may already exist.', 'danger')
    form.username.data = user.username
    form.email.data = user.email
    form.role.data = user.role
    return render_template('register.html', form=form)

@app.route('/delete_user/<username>', methods=['POST'])
@role_required('admin')
def delete_user(username):
    user = User.query.filter_by(username=username).first()
    if user:
        try:
            db.session.delete(user)
            db.session.commit()
            flash('User deleted successfully!', 'success')
        except Exception as e:
            logger.error(f"Delete user error: {e}")
            flash('Failed to delete user.', 'danger')
    else:
        flash('User not found', 'danger')
    return redirect(url_for('admin_dashboard'))

@app.route('/manage_cards', methods=['GET', 'POST'])
@role_required('client')
def manage_cards():
    form = CardForm()
    if form.validate_on_submit():
        card = Card(
            card_number=form.card_number.data,
            cardholder_name=form.cardholder_name.data,
            user_id=session['user_id']
        )
        try:
            db.session.add(card)
            db.session.commit()
            flash('Card added successfully!', 'success')
            return redirect(url_for('manage_cards'))
        except Exception as e:
            db.session.rollback()
            logger.error(f"Add card error: {e}")
            flash('Failed to add card. Card number may already exist.', 'danger')
    cards = Card.query.filter_by(user_id=session['user_id']).all()
    return render_template('manage_cards.html', form=form, cards=cards)

@app.route('/transfer_balance', methods=['GET', 'POST'])
@role_required('client')
def transfer_balance():
    form = TransferForm()
    if form.validate_on_submit():
        sender_card = Card.query.filter_by(card_number=form.sender_card_number.data, user_id=session['user_id']).first()
        receiver_card = Card.query.filter_by(card_number=form.receiver_card_number.data).first()
        if not sender_card:
            flash('Invalid sender card number', 'danger')
            return redirect(url_for('transfer_balance'))
        if not receiver_card:
            flash('Invalid receiver card number', 'danger')
            return redirect(url_for('transfer_balance'))
        if sender_card.balance < form.amount.data:
            flash('Insufficient balance in the sender card', 'danger')
            return redirect(url_for('transfer_balance'))
        if form.amount.data <= 0:
            flash('Amount must be greater than zero', 'danger')
            return redirect(url_for('transfer_balance'))
        try:
            sender_card.balance -= form.amount.data
            receiver_card.balance += form.amount.data
            transaction = Transaction(
                user_id=sender_card.user_id,
                amount=form.amount.data,
                transaction_type='transfer',
                card_number=sender_card.card_number
            )
            transfer = Transfer(
                sender_card_number=sender_card.card_number,
                receiver_card_number=receiver_card.card_number,
                amount=form.amount.data
            )
            db.session.add(transaction)
            db.session.add(transfer)
            db.session.commit()
            flash('Transfer successful!', 'success')
            return redirect(url_for('manage_cards'))
        except Exception as e:
            db.session.rollback()
            logger.error(f"Transfer error: {e}")
            flash('Transfer failed. Please try again.', 'danger')
    return render_template('transfer_balance.html', form=form)

@app.route('/transactions', methods=['GET', 'POST'])
@role_required('client')
def transactions():
    form = TransactionForm()
    if request.is_json:
        data = request.get_json()
        card_number = data.get('card_number')
        amount = data.get('amount')
        transaction_type = data.get('transaction_type')
        card = Card.query.filter_by(card_number=card_number, user_id=session['user_id']).first()
        if not card:
            return jsonify({'error': 'Invalid card number'}), 400
        if amount <= 0:
            return jsonify({'error': 'Amount must be greater than zero'}), 400
        if transaction_type != 'topup' and card.balance < amount:
            return jsonify({'error': 'Insufficient balance'}), 400
        try:
            transaction = Transaction(
                user_id=session['user_id'],
                amount=amount,
                transaction_type=transaction_type,
                card_number=card_number
            )
            if transaction_type == 'topup':
                card.balance += amount
            else:
                card.balance -= amount
            db.session.add(transaction)
            db.session.commit()
            return jsonify({'message': 'Transaction successful', 'new_balance': card.balance}), 200
        except Exception as e:
            db.session.rollback()
            logger.error(f"API transaction error: {e}")
            return jsonify({'error': 'Transaction failed', 'details': str(e)}), 500
    if form.validate_on_submit():
        card = Card.query.filter_by(card_number=form.card_number.data, user_id=session['user_id']).first()
        if not card:
            flash('Invalid card number', 'danger')
            return redirect(url_for('transactions'))
        if form.amount.data <= 0:
            flash('Amount must be greater than zero', 'danger')
            return redirect(url_for('transactions'))
        if form.transaction_type.data != 'topup' and card.balance < form.amount.data:
            flash('Insufficient balance', 'danger')
            return redirect(url_for('transactions'))
        try:
            transaction = Transaction(
                user_id=session['user_id'],
                amount=form.amount.data,
                transaction_type=form.transaction_type.data,
                card_number=form.card_number.data
            )
            if form.transaction_type.data == 'topup':
                card.balance += form.amount.data
            else:
                card.balance -= form.amount.data
            db.session.add(transaction)
            db.session.commit()
            flash('Transaction successful!', 'success')
            return redirect(url_for('transactions'))
        except Exception as e:
            db.session.rollback()
            logger.error(f"Form transaction error: {e}")
            flash('Transaction failed. Please try again.', 'danger')
    transactions = Transaction.query.filter_by(user_id=session['user_id']).all()
    return render_template('transactions.html', form=form, transactions=transactions)

@app.route('/add_card', methods=['GET', 'POST'])
@role_required('client')
def add_card():
    form = CardForm()
    if form.validate_on_submit():
        card = Card(
            card_number=form.card_number.data,
            cardholder_name=form.cardholder_name.data,
            user_id=session['user_id']
        )
        try:
            db.session.add(card)
            db.session.commit()
            flash('Card added successfully!', 'success')
            return redirect(url_for('manage_cards'))
        except Exception as e:
            db.session.rollback()
            logger.error(f"Add card error: {e}")
            flash('Failed to add card. Card number may already exist.', 'danger')
    return render_template('add_card.html', form=form)

@app.route('/topup', methods=['POST'])
@role_required('client')
def topup():
    try:
        data = request.get_json()
        card_number = data.get('card_number')
        topup_amount = data.get('amount')
        if not card_number or not topup_amount:
            return jsonify({'error': 'Card number and amount are required'}), 400
        if topup_amount <= 0:
            return jsonify({'error': 'Top-up amount must be greater than zero'}), 400
        card = Card.query.filter_by(card_number=card_number, user_id=session['user_id']).first()
        if not card:
            return jsonify({'error': 'Card not found'}), 404
        try:
            card.balance += topup_amount
            transaction = Transaction(
                user_id=session['user_id'],
                amount=topup_amount,
                transaction_type='topup',
                card_number=card_number
            )
            db.session.add(transaction)
            db.session.commit()
            return jsonify({'message': 'Top-up successful', 'new_balance': card.balance}), 200
        except Exception as e:
            db.session.rollback()
            logger.error(f"Topup error: {e}")
            return jsonify({'error': 'Top-up failed'}), 500
    except Exception as e:
        logger.error(f"Topup request error: {e}")
        return jsonify({'error': str(e)}), 400

@app.route('/transfers')
@role_required('client')
def transfers():
    transfers = Transfer.query.filter_by(sender_card_number=Card.query.filter_by(user_id=session['user_id']).first().card_number).order_by(Transfer.date.desc()).all()
    return render_template('transfers.html', transfers=transfers)

@app.route('/calculate_expenses', methods=['GET'])
@role_required('client')
def calculate_expenses():
    user_id = session['user_id']
    total_expenses = db.session.query(func.sum(Transfer.amount)).filter(
        Transfer.sender_card_number == Card.query.filter_by(user_id=user_id).first().card_number
    ).scalar() or 0.0
    return render_template('calculate_expenses.html', total_expenses=total_expenses)

@app.route('/request_report', methods=['GET', 'POST'])
@role_required('client')
def request_report():
    form = EmailRequestForm()
    user = User.query.get(session['user_id'])
    if form.validate_on_submit():
        recipient_email = form.recipient_email.data
        result = send_user_report(session['user_id'], recipient_email)
        if result == "Email sent successfully":
            flash('Report sent successfully to your email!', 'success')
        else:
            flash(result, 'danger')
        return redirect(url_for('client_dashboard'))
    form.recipient_email.data = user.email
    return render_template('request_report.html', form=form)

@app.route('/logout')
def logout():
    session.pop('username', None)
    session.pop('role', None)
    session.pop('user_id', None)
    flash('You have been logged out.', 'success')
    return redirect(url_for('home'))

@app.route('/monthly_transactions')
@role_required('client')
def monthly_transactions():
    user_id = session['user_id']
    transactions = db.session.query(
        Transfer.sender_card_number,
        func.strftime('%Y-%m', Transfer.date).label('month'),
        func.sum(Transfer.amount).label('total_amount')
    ).filter(
        Transfer.sender_card_number == Card.query.filter_by(user_id=user_id).first().card_number
    ).group_by(
        Transfer.sender_card_number, func.strftime('%Y-%m', Transfer.date)
    ).order_by(
        Transfer.sender_card_number, func.strftime('%Y-%m', Transfer.date)
    ).all()
    cards = {}
    for transaction in transactions:
        card_number = transaction.sender_card_number
        month = transaction.month
        amount = float(transaction.total_amount)
        if card_number not in cards:
            cards[card_number] = {'months': [], 'amounts': []}
        cards[card_number]['months'].append(month)
        cards[card_number]['amounts'].append(amount)
    return render_template('monthly_transactions.html', cards=cards)

@app.route('/predict', methods=['POST'])
@role_required('client')
def predict():
    try:
        distance = float(request.form['distance'])
        fuel_price = float(request.form['fuel_price'])
        trips_per_day = int(request.form['trips_per_day'])
        peak_off_peak = int(request.form['peak_off_peak'])
        inputs = {
            'Distance': distance,
            'Fuel_Price': fuel_price,
            'Trips_Per_Day': trips_per_day,
            'Peak/Off-Peak': peak_off_peak
        }
        inputs_df = pd.DataFrame([inputs])
        forecast_steps = 1
        forecast = model.forecast(steps=forecast_steps)
        return render_template('result.html', forecasted_cost=forecast[0])
    except Exception as e:
        logger.error(f"Predict error: {e}")
        flash('Prediction failed. Please check your inputs.', 'danger')
        return redirect(url_for('client_dashboard'))

@app.route('/predictx', methods=['POST'])
@role_required('client')
def predictx():
    try:
        data = request.get_json()
        logger.info(f"Received predictx data: {data}")
        inputs = data['inputs']
        inputs_df = pd.DataFrame(inputs)
        forecast_steps = 1
        forecast = model.forecast(steps=forecast_steps)
        return jsonify({'forecasted_cost': forecast[0]})
    except Exception as e:
        logger.error(f"Predictx error: {e}")
        return jsonify({'error': str(e)}), 400

@app.route('/card-details', methods=['POST'])
@role_required('client')
def card_details():
    try:
        data = request.get_json()
        card_number = data.get('card_number')
        if not card_number:
            return jsonify({'error': 'Card number is required'}), 400
        query = text("""
            SELECT 
                c.card_number, 
                c.cardholder_name, 
                c.balance,
                IFNULL(SUM(t.amount), 0) AS total_monthly_transactions
            FROM card c
            LEFT JOIN "transaction" t 
                ON c.card_number = t.card_number 
                AND strftime('%Y-%m', t.timestamp) = strftime('%Y-%m', :current_date)
            WHERE c.card_number = :card_number
            GROUP BY c.card_number, c.cardholder_name, c.balance
        """)
        result = db.session.execute(query, {
            'card_number': card_number,
            'current_date': datetime.now().strftime('%Y-%m-%d')
        }).fetchone()
        if not result:
            return jsonify({'error': 'Card not found'}), 404
        card_details = {
            'card_number': result.card_number,
            'cardholder_name': result.cardholder_name,
            'balance': result.balance,
            'total_monthly_transactions': result.total_monthly_transactions
        }
        return jsonify(card_details)
    except Exception as e:
        logger.error(f"Card details error: {e}")
        return jsonify({'error': str(e)}), 500

@app.route('/predict-cost', methods=['POST'])
@role_required('client')
def predict_cost():
    try:
        data = request.get_json()
        card_number = data.get('card_number')
        if not card_number:
            return jsonify({'error': 'Card number is required'}), 400
        query = text("""
            SELECT 
                IFNULL(SUM(t.amount), 0) AS total_monthly_transactions
            FROM "transaction" t 
            WHERE t.card_number = :card_number 
              AND strftime('%Y-%m', t.timestamp) = strftime('%Y-%m', :current_date)
        """)
        result = db.session.execute(query, {
            'card_number': card_number,
            'current_date': datetime.now().strftime('%Y-%m-%d')
        }).fetchone()
        if not result:
            return jsonify({'error': 'No transactions found for this card'}), 404
        total_monthly_transactions = result.total_monthly_transactions
        forecast = model.forecast(steps=1, exog=[[total_monthly_transactions]])
        return jsonify({
            'card_number': card_number,
            'total_monthly_transactions': total_monthly_transactions,
            'forecasted_cost': forecast[0]
        })
    except Exception as e:
        logger.error(f"Predict cost error: {e}")
        return jsonify({'error': str(e)}), 500

@app.route('/card-and-predict', methods=['POST'])
@role_required('client')
def card_and_predict():
    try:
        data = request.get_json()
        card_number = data.get('card_number')
        if not card_number:
            return jsonify({'error': 'Card number is required'}), 400
        query = text("""
            SELECT 
                c.card_number, 
                c.cardholder_name, 
                c.balance,
                IFNULL(SUM(t.amount), 0) AS total_monthly_transactions
            FROM card c
            LEFT JOIN "transaction" t 
                ON c.card_number = t.card_number 
                AND strftime('%Y-%m', t.timestamp) = strftime('%Y-%m', :current_date)
            WHERE c.card_number = :card_number
            GROUP BY c.card_number, c.cardholder_name, c.balance
        """)
        result = db.session.execute(query, {
            'card_number': card_number,
            'current_date': datetime.now().strftime('%Y-%m-%d')
        }).fetchone()
        if not result:
            return jsonify({'error': 'Card not found'}), 404
        card_details = {
            'card_number': result.card_number,
            'cardholder_name': result.cardholder_name,
            'balance': result.balance,
            'total_monthly_transactions': result.total_monthly_transactions
        }
        forecast = model.forecast(steps=1, exog=[[result.total_monthly_transactions]])
        card_details['predicted_cost'] = forecast[0]
        return jsonify(card_details)
    except Exception as e:
        logger.error(f"Card and predict error: {e}")
        return jsonify({'error': str(e)}), 500

@app.route('/card-details-ui')
@role_required('client')
def card_details_ui():
    return render_template('card_details.html')

@app.route('/capredict', methods=['GET'])
@role_required('client')
def capredict():
    try:
        query = text("""
            SELECT 
                c.card_number, 
                c.cardholder_name, 
                c.balance,
                IFNULL(SUM(t.amount), 0) AS total_monthly_transactions
            FROM card c
            LEFT JOIN "transaction" t 
                ON c.card_number = t.card_number 
                AND strftime('%Y-%m', t.timestamp) = strftime('%Y-%m', :current_date)
            GROUP BY c.card_number, c.cardholder_name, c.balance
        """)
        results = db.session.execute(query, {
            'current_date': datetime.now().strftime('%Y-%m-%d')
        }).fetchall()
        if not results:
            return jsonify({'error': 'No cards found'}), 404
        all_card_details = []
        for result in results:
            card_details = {
                'card_number': result.card_number,
                'cardholder_name': result.cardholder_name,
                'balance': result.balance,
                'total_monthly_transactions': result.total_monthly_transactions
            }
            forecast = model.forecast(steps=1, exog=[[result.total_monthly_transactions]])
            card_details['predicted_cost'] = forecast[0]
            all_card_details.append(card_details)
        return jsonify(all_card_details)
    except Exception as e:
        logger.error(f"Capredict error: {e}")
        return jsonify({'error': str(e)}), 500

@app.route('/cardpredict/<card_number>', methods=['GET'])
@role_required('client')
def cardpredict(card_number):
    try:
        query = text("""
            SELECT 
                c.card_number, 
                c.cardholder_name, 
                c.balance,
                IFNULL(SUM(t.amount), 0) AS total_monthly_transactions
            FROM card c
            LEFT JOIN "transaction" t 
                ON c.card_number = t.card_number 
                AND strftime('%Y-%m', t.timestamp) = strftime('%Y-%m', :current_date)
            WHERE c.card_number = :card_number
            GROUP BY c.card_number, c.cardholder_name, c.balance
        """)
        result = db.session.execute(query, {
            'card_number': card_number,
            'current_date': datetime.now().strftime('%Y-%m-%d')
        }).fetchone()
        if not result:
            return jsonify({'error': 'Card not found'}), 404
        card_details = {
            'card_number': result.card_number,
            'cardholder_name': result.cardholder_name,
            'balance': result.balance,
            'total_monthly_transactions': result.total_monthly_transactions
        }
        forecast = model.forecast(steps=1, exog=[[result.total_monthly_transactions]])
        card_details['predicted_cost'] = forecast[0]
        return jsonify(card_details)
    except Exception as e:
        logger.error(f"Cardpredict error: {e}")
        return jsonify({'error': str(e)}), 500

@app.route('/view-cards')
@role_required('client')
def view_cards():
    return render_template('card_and_predict.html')

@app.route('/manage_users')
@role_required('admin')
def manage_users():
    users = User.query.all()
    transfers = Transfer.query.order_by(Transfer.date.desc()).all()
    return render_template('manage_users.html', users=users, transfers=transfers)

@app.route('/admin/view_users', methods=['GET'])
@role_required('admin')
def view_users_and_cards():
    try:
        users_with_cards = db.session.query(User, Card).outerjoin(Card, User.id == Card.user_id).all()
        users_data = {}
        for user, card in users_with_cards:
            if user.id not in users_data:
                users_data[user.id] = {
                    'username': user.username,
                    'email': user.email,
                    'role': user.role,
                    'cards': []
                }
            if card:
                query = text("""
                    SELECT IFNULL(SUM(amount), 0) AS total_monthly_transactions
                    FROM "transaction"
                    WHERE card_number = :card_number
                    AND strftime('%Y-%m', timestamp) = strftime('%Y-%m', :current_date)
                """)
                total_monthly_transactions = db.session.execute(query, {
                    'card_number': card.card_number,
                    'current_date': datetime.now().strftime('%Y-%m-%d')
                }).scalar()
                predicted_cost = model.forecast(steps=1, exog=[[total_monthly_transactions]])[0]
                users_data[user.id]['cards'].append({
                    'card_number': card.card_number,
                    'cardholder_name': card.cardholder_name,
                    'balance': card.balance,
                    'expiry_date': card.expiry_date,
                    'total_monthly_transactions': total_monthly_transactions,
                    'predicted_cost': predicted_cost
                })
        return render_template('view_users.html', users=users_data.values())
    except Exception as e:
        logger.error(f"View users error: {e}")
        flash('An error occurred while loading users and cards.', 'danger')
        return redirect(url_for('admin_dashboard'))

@app.route('/admin/admanage_cards', methods=['GET', 'POST'])
@role_required('admin')
def admanage_cards():
    try:
        search_query = request.args.get('search', '')
        if search_query:
            cards = Card.query.filter(
                db.or_(
                    Card.card_number.ilike(f"%{search_query}%"),
                    Card.cardholder_name.ilike(f"%{search_query}%")
                )
            ).all()
        else:
            cards = Card.query.all()
        cards_with_predictions = []
        for card in cards:
            query = text("""
                SELECT IFNULL(SUM(amount), 0) AS total_monthly_transactions
                FROM "transaction"
                WHERE card_number = :card_number
                AND strftime('%Y-%m', timestamp) = strftime('%Y-%m', :current_date)
            """)
            total_monthly_transactions = db.session.execute(query, {
                'card_number': card.card_number,
                'current_date': datetime.now().strftime('%Y-%m-%d')
            }).scalar()
            predicted_cost = model.forecast(steps=1, exog=[[total_monthly_transactions]])[0]
            cards_with_predictions.append({
                'id': card.id,
                'card_number': card.card_number,
                'cardholder_name': card.cardholder_name,
                'balance': card.balance,
                'expiry_date': card.expiry_date,
                'total_monthly_transactions': total_monthly_transactions,
                'predicted_cost': predicted_cost
            })
        return render_template('admanage_cards.html', cards=cards_with_predictions, search_query=search_query)
    except Exception as e:
        logger.error(f"Manage cards error: {e}")
        flash('An error occurred while managing cards.', 'danger')
        return redirect(url_for('admin_dashboard'))

@app.route('/admin/delete_card/<int:card_id>', methods=['POST'])
@role_required('admin')
def delete_card(card_id):
    try:
        card = Card.query.get(card_id)
        if not card:
            flash('Card not found.', 'danger')
            return redirect(url_for('admanage_cards'))
        db.session.delete(card)
        db.session.commit()
        flash(f"Card '{card.card_number}' deleted successfully.", 'success')
    except Exception as e:
        logger.error(f"Delete card error: {e}")
        flash('Failed to delete card.', 'danger')
    return redirect(url_for('admanage_cards'))

@app.route('/create', methods=['GET', 'POST'])
@role_required('admin')
def create_transfer():
    form = TransferForm()
    if form.validate_on_submit():
        sender_card = Card.query.filter_by(card_number=form.sender_card_number.data).first()
        receiver_card = Card.query.filter_by(card_number=form.receiver_card_number.data).first()
        if not sender_card:
            flash('Invalid sender card number', 'danger')
            return redirect(url_for('create_transfer'))
        if not receiver_card:
            flash('Invalid receiver card number', 'danger')
            return redirect(url_for('create_transfer'))
        if sender_card.balance < form.amount.data:
            flash('Insufficient balance in the sender card', 'danger')
            return redirect(url_for('create_transfer'))
        if form.amount.data <= 0:
            flash('Amount must be greater than zero', 'danger')
            return redirect(url_for('create_transfer'))
        try:
            sender_card.balance -= form.amount.data
            receiver_card.balance += form.amount.data
            transaction = Transaction(
                user_id=sender_card.user_id,
                amount=form.amount.data,
                transaction_type='transfer',
                card_number=sender_card.card_number
            )
            transfer = Transfer(
                sender_card_number=form.sender_card_number.data,
                receiver_card_number=form.receiver_card_number.data,
                amount=form.amount.data
            )
            db.session.add(transaction)
            db.session.add(transfer)
            db.session.commit()
            flash('Transfer created successfully!', 'success')
            return redirect(url_for('admin_dashboard'))
        except Exception as e:
            db.session.rollback()
            logger.error(f"Create transfer error: {e}")
            flash('Failed to create transfer.', 'danger')
    return render_template('create_transfer.html', form=form)

@app.route('/transfer/<int:transfer_id>')
@role_required('admin')
def transfer_details(transfer_id):
    transfer = Transfer.query.get_or_404(transfer_id)
    return render_template('transfer_details.html', transfer=transfer)

# Error handler
@app.errorhandler(Exception)
def handle_error(error):
    logger.error(f"Unhandled error: {error}")
    return jsonify({'error': 'An unexpected error occurred', 'details': str(error)}), 500

if __name__ == '__main__':
    with app.app_context():
        db.create_all()
    app.run(host='0.0.0.0', port=5000, debug=False)
