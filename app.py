from flask import Flask, render_template, redirect, url_for, flash, request, session, jsonify
from flask_sqlalchemy import SQLAlchemy
from flask_wtf import FlaskForm
from wtforms import StringField, PasswordField, SelectField, SubmitField, FloatField
from wtforms.validators import DataRequired, Length
from werkzeug.security import generate_password_hash, check_password_hash
import os
from datetime import datetime, date, timedelta
from functools import wraps
from datetime import datetime
from sqlalchemy import func
from flask import Flask, request, jsonify
import joblib
import numpy as np
import pandas as pd
from sqlalchemy.sql import text
from flask_wtf.csrf import CSRFProtect
from flask_mail import Mail, Message
import threading
import time
app = Flask(__name__)
csrf = CSRFProtect(app)
app.config['SECRET_KEY'] = 'your_secret_key'
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///site.db'
app.config['UPLOAD_FOLDER'] = 'static/uploads'
os.makedirs(app.config['UPLOAD_FOLDER'], exist_ok=True)
db = SQLAlchemy(app)
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///your_database.db'  # Replace with your database URI
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///your_database.db'
app.config['MAIL_SERVER'] = 'mail.vrt.rw'
app.config['MAIL_PORT'] = 587
app.config['MAIL_USE_TLS'] = True
app.config['MAIL_USERNAME'] = 'info@vrt.rw'
app.config['MAIL_PASSWORD'] = 'TheGreat@123'
mail = Mail(app)

roles = [('admin', 'Admin'), ('vender_machine', 'vender_machine'), ('client', 'client')]
model = joblib.load('arima_model.pkl')
# User model
class User(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(25), unique=True, nullable=False)
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

# File upload model
class FileUpload(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    filename = db.Column(db.String(100), nullable=False)
    description = db.Column(db.String(200), nullable=False)
    username = db.Column(db.String(25), db.ForeignKey('user.username'), nullable=False)

    def __repr__(self):
        return f"FileUpload('{self.filename}', '{self.description}', '{self.username}')"

# Payment card model
from datetime import date, timedelta

class Card(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    card_number = db.Column(db.String, nullable=False, unique=True)
    cardholder_name = db.Column(db.String, nullable=False)
    balance = db.Column(db.Float, default=0.0)
    expiry_date = db.Column(db.Date, nullable=False, default=lambda: date.today() + timedelta(days=3*365))
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)

    def __repr__(self):
        return f"Card('{self.card_number}', '{self.cardholder_name}', '{self.balance}')"

# Transaction model
class Transaction(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    amount = db.Column(db.Float, nullable=False)
    transaction_type = db.Column(db.String, nullable=False)
    card_number = db.Column(db.String, nullable=True)  # Make sure this line exists
    timestamp = db.Column(db.DateTime, default=datetime.utcnow)

    def __repr__(self):
        return f"Transaction('{self.amount}', '{self.transaction_type}', '{self.timestamp}')"

# Forms for registration, login, upload, and payment card
class RegistrationForm(FlaskForm):
    username = StringField('Username', validators=[DataRequired(), Length(min=3, max=25)])
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
    card_number = StringField('Card Number', validators=[DataRequired()])
    cardholder_name = StringField('Cardholder Name', validators=[DataRequired()])
    
    submit = SubmitField('Add Card')

class TransactionForm(FlaskForm):
    card_number = StringField('Card Number', validators=[DataRequired()])
    amount = FloatField('Amount', validators=[DataRequired()])
    transaction_type = SelectField('Transaction Type', choices=[('topup', 'Top Up'), ('purchase', 'Purchase'), ('transfer', 'Transfer')], validators=[DataRequired()])
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
# Decorator to check user role
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



# Routes for the application
@app.route('/')
def home():
    return render_template('homepage.html')

@app.route('/register', methods=['GET', 'POST'])
def register():
    form = RegistrationForm()
    if form.validate_on_submit():
        hashed_password = generate_password_hash(form.password.data, method='pbkdf2:sha256')
        user = User(username=form.username.data, password=hashed_password, role=form.role.data)
        db.session.add(user)
        db.session.commit()
        flash('Registration successful! You can now log in.', 'success')
        return redirect(url_for('login'))
    return render_template('register.html', form=form)

@app.route('/login', methods=['GET', 'POST'])
def login():
    form = LoginForm()
    if form.validate_on_submit():
        user = User.query.filter_by(username=form.username.data).first()
        if user and check_password_hash(user.password, form.password.data):
            session['username'] = user.username
            session['role'] = user.role
            session['user_id'] = user.id  # Store user ID in session
            return redirect(url_for('dashboard'))
        else:
            flash('Login failed. Check your username and password.', 'danger')
    return render_template('login.html', form=form)

@app.route('/dashboard')
def dashboard():
    if 'username' in session:
        username = session['username']
        role = session['role']
        if role == 'admin':
            return redirect(url_for('admin_dashboard'))
        elif role == 'client':
            return redirect(url_for('client_dashboard'))
        elif role == 'vender_machine':
            return redirect(url_for('vender_machine_dashboard'))
        flash('Role not recognized', 'danger')
        return redirect(url_for('home'))
    return redirect(url_for('login'))
@app.route('/admin_dashboard')
@role_required('admin')  # Custom decorator to restrict access to admins
def admin_dashboard():
    if 'username' in session:
        username = session['username']

        try:
            # Fetch core data
            users = User.query.all()
            uploads = FileUpload.query.all()
            transactions = Transaction.query.order_by(Transaction.timestamp.desc()).limit(10).all()

            # Aggregate data for overview
            total_users = User.query.count()
            total_uploads = FileUpload.query.count()
            total_transactions = Transaction.query.count()

            # Data for charts
            user_roles_count = db.session.query(User.role, db.func.count(User.id)).group_by(User.role).all()
            transactions_by_type = db.session.query(Transaction.transaction_type, db.func.sum(Transaction.amount)).group_by(Transaction.transaction_type).all()

            # Convert query results to dictionaries for frontend
            roles_data = {role: count for role, count in user_roles_count} if user_roles_count else {"No Data": 0}
            transactions_data = {t_type: amount for t_type, amount in transactions_by_type} if transactions_by_type else {"No Data": 0}

            return render_template(
                'admin_dashboard.html',
                username=username,
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
            # Log the error and show a flash message
            app.logger.error(f"Error loading admin dashboard: {e}")
            flash('An error occurred while loading the admin dashboard.', 'danger')
            return redirect(url_for('home'))

    # Redirect to login if session is invalid
    return redirect(url_for('login'))


@app.route('/client_dashboard')
@role_required('client')
def client_dashboard():
    if 'username' in session:
        username = session['username']
        search_query = request.args.get('search', '').lower()
        vender_machine_uploads = db.session.query(FileUpload, User).join(User).filter(
            User.role == 'vender_machine', 
            (FileUpload.filename.ilike(f"%{search_query}%") | FileUpload.description.ilike(f"%{search_query}%"))
        ).all()

        uploads = [
            {'filename': upload.filename, 
             'description': upload.description, 
             'username': user.username} 
            for upload, user in vender_machine_uploads
        ]

        return render_template('client_dashboard.html', username=username, uploads=uploads)
    return redirect(url_for('login'))

@app.route('/vender_machine_dashboard')
@role_required('vender_machine')
def vender_machine_dashboard():
    if 'username' in session:
        username = session['username']
        user_uploads = FileUpload.query.filter_by(username=username).all()
        return render_template('vender_machine_dashboard.html', username=username, uploads=user_uploads)
    return redirect(url_for('login'))

@app.route('/create_user', methods=['GET', 'POST'])
@role_required('admin')
def create_user():
    form = RegistrationForm()
    if form.validate_on_submit():
        hashed_password = generate_password_hash(form.password.data, method='pbkdf2:sha256')
        user = User(username=form.username.data, password=hashed_password, role=form.role.data)
        db.session.add(user)
        db.session.commit()
        flash('User created successfully!', 'success')
        return redirect(url_for('admin_dashboard'))
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
        user.role = form.role.data
        if form.password.data:
            user.password = generate_password_hash(form.password.data, method='pbkdf2:sha256')
        db.session.commit()
        flash('User updated successfully!', 'success')
        return redirect(url_for('admin_dashboard'))
    # Pre    # Pre-fill the form with existing user data
    form.username.data = user.username
    form.role.data = user.role
    return render_template('register.html', form=form)

@app.route('/delete_user/<username>', methods=['POST'])
@role_required('admin')
def delete_user(username):
    user = User.query.filter_by(username=username).first()
    if user:
        db.session.delete(user)
        db.session.commit()
        flash('User deleted successfully!', 'success')
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
        db.session.add(card)
        db.session.commit()
        flash('Card added successfully!', 'success')
        return redirect(url_for('manage_cards'))

    cards = Card.query.filter_by(user_id=session['user_id']).all()
    return render_template('manage_cards.html', form=form, cards=cards)

# @app.route('/transfer_balance', methods=['GET', 'POST'])
# @role_required('client')
# def transfer_balance():
#     form = TransferForm()

#     if form.validate_on_submit():
#         sender_card = Card.query.filter_by(card_number=form.sender_card_number.data, user_id=session['user_id']).first()
#         receiver_card = Card.query.filter_by(card_number=form.receiver_card_number.data).first()

#         if not sender_card:
#             flash('Invalid sender card number', 'danger')
#             return redirect(url_for('transfer_balance'))

#         if not receiver_card:
#             flash('Invalid receiver card number', 'danger')
#             return redirect(url_for('transfer_balance'))

#         if sender_card.balance < form.amount.data:
#             flash('Insufficient balance in the sender card', 'danger')
#             return redirect(url_for('transfer_balance'))

#         # Deduct from sender and add to receiver
#         sender_card.balance -= form.amount.data
#         receiver_card.balance += form.amount.data

#         # Log the transaction for the sender
#         transaction = Transaction(
#             user_id=sender_card.user_id,
#             amount=form.amount.data,
#             transaction_type='transfer',
#             card_number=sender_card.card_number
#         )
#         db.session.add(transaction)

#         # Commit changes
#         db.session.commit()

#         flash('Transfer successful!', 'success')
#         return redirect(url_for('manage_cards'))

#     return render_template('transfer_balance.html', form=form)

# Transfer route
@app.route('/transfer_balance', methods=['GET', 'POST'])
@role_required('client')
def transfer_balance():
    form = TransferForm()

    if form.validate_on_submit():
        # Find the sender card belonging to the current user
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

        # Deduct from sender and add to receiver
        sender_card.balance -= form.amount.data
        receiver_card.balance += form.amount.data

        # Log the transaction for the sender
        transaction = Transaction(
            user_id=sender_card.user_id,
            amount=form.amount.data,
            transaction_type='transfer',
            card_number=sender_card.card_number
        )
        db.session.add(transaction)

        # Commit changes
        db.session.commit()

        flash('Transfer successful!', 'success')
        return redirect(url_for('manage_cards'))

    return render_template('transfer_balance.html', form=form)




# @app.route('/transactions', methods=['GET', 'POST'])
# @role_required('client')
# def transactions():
#     form = TransactionForm()

#     if form.validate_on_submit():
#         # Ensure card exists
#         card = Card.query.filter_by(card_number=form.card_number.data).first()
#         if not card:
#             flash('Invalid card number', 'danger')
#             return redirect(request.url)

#         # Check for sufficient balance
#         if card.balance < form.amount.data:
#             flash('Insufficient balance', 'danger')
#             return redirect(request.url)

#         # Process transaction
#         try:
#             transaction = Transaction(
#                 user_id=session['user_id'],
#                 amount=form.amount.data,
#                 transaction_type=form.transaction_type.data,
#                 card_number=form.card_number.data
#             )
#             card.balance -= form.amount.data  # Deduct amount from card balance
#             db.session.add(transaction)
#             db.session.commit()
#             flash('Transaction successful!', 'success')
#             return redirect(url_for('transactions'))
#         except Exception as e:
#             db.session.rollback()
#             flash('Transaction failed. Please try again.', 'danger')
#             return redirect(url_for('transactions'))

#     transactions = Transaction.query.filter_by(user_id=session['user_id']).all()
#     return render_template('transactions.html', form=form, transactions=transactions)
from flask import jsonify

@app.route('/transactions', methods=['GET', 'POST'])
@role_required('client')
def transactions():
    form = TransactionForm()

    # Handle API request (JSON)
    if request.is_json:
        data = request.get_json()
        card_number = data.get('card_number')
        amount = data.get('amount')
        transaction_type = data.get('transaction_type')

        # Ensure card exists
        card = Card.query.filter_by(card_number=card_number, user_id=session['user_id']).first()
        if not card:
            return jsonify({'error': 'Invalid card number'}), 400

        # Check for sufficient balance
        if card.balance < amount:
            return jsonify({'error': 'Insufficient balance'}), 400

        # Process transaction
        try:
            transaction = Transaction(
                user_id=session['user_id'],
                amount=amount,
                transaction_type=transaction_type,
                card_number=card_number
            )
            card.balance -= amount  # Deduct amount from card balance
            db.session.add(transaction)
            db.session.commit()
            return jsonify({'message': 'Transaction successful', 'new_balance': card.balance}), 200
        except Exception as e:
            db.session.rollback()
            return jsonify({'error': 'Transaction failed', 'details': str(e)}), 500

    # Handle form submission
    if form.validate_on_submit():
        # Ensure card exists
        card = Card.query.filter_by(card_number=form.card_number.data, user_id=session['user_id']).first()
        if not card:
            flash('Invalid card number', 'danger')
            return redirect(request.url)

        # Check for sufficient balance
        if card.balance < form.amount.data:
            flash('Insufficient balance', 'danger')
            return redirect(request.url)

        # Process transaction
        try:
            transaction = Transaction(
                user_id=session['user_id'],
                amount=form.amount.data,
                transaction_type=form.transaction_type.data,
                card_number=form.card_number.data
            )
            card.balance -= form.amount.data  # Deduct amount from card balance
            db.session.add(transaction)
            db.session.commit()
            flash('Transaction successful!', 'success')
            return redirect(url_for('transactions'))
        except Exception as e:
            db.session.rollback()
            flash('Transaction failed. Please try again.', 'danger')
            return redirect(url_for('transactions'))

    # Retrieve transactions for the current user
    transactions = Transaction.query.filter_by(user_id=session['user_id']).all()
    return render_template('transactions.html', form=form, transactions=transactions)

@app.route('/add_card', methods=['POST'])
@csrf.exempt 
def add_card():
    if request.method == 'POST':
        card_number = request.form.get('card_number')
        cardholder_name = request.form.get('cardholder_name')
    

        # Input validation (basic example)
        if not card_number or not cardholder_name or not expiry_date or not cvv:
            return "All fields are required.", 400

        try:
            # Assume db is your database connection
            db.execute("INSERT INTO cards (card_number, cardholder_name, expiry_date, cvv) VALUES (?, ?, ?, ?)",
                       (card_number, cardholder_name, expiry_date, cvv))
            db.commit()  # Commit the transaction
            return "Card added successfully.", 201
        except Exception as e:
            db.rollback()  # Rollback in case of error
            return str(e), 500

# @app.route('/topup', methods=['POST'])
# def topup():
#     try:
#         # Get card number and top-up amount from the request JSON body
#         data = request.get_json()
#         card_number = data.get('card_number')
#         topup_amount = data.get('amount')

#         if not card_number or not topup_amount:
#             return jsonify({'error': 'Card number and amount are required'}), 400

#         # Fetch the card details from the database
#         card = Card.query.filter_by(card_number=card_number).first()

#         if not card:
#             return jsonify({'error': 'Card not found'}), 404

#         # Check if the current balance is greater than zero
#         if card.balance < 0:
#             return jsonify({'error': 'You can only top up if your balance is greater than zero'}), 400

#         # Perform the top-up
#         card.balance += topup_amount  # Add the top-up amount to the card balance
#         db.session.commit()  # Save changes to the database

#         # Return success response
#         return jsonify({'message': 'Top-up successful', 'new_balance': card.balance}), 200

#     except Exception as e:
#         return jsonify({'error': str(e)}), 500
# @app.route('/topup', methods=['POST'])
# def topup():
#     try:
#         # Get the card number and top-up amount from the request JSON body
#         data = request.get_json()  # Fetch JSON payload from the request body
#         card_number = data.get('card_number')
#         topup_amount = data.get('amount')

#         # Ensure card_number and amount are present
#         if not card_number or not topup_amount:
#             return jsonify({'error': 'Card number and amount are required'}), 400

#         # Fetch the card details from the database
#         card = Card.query.filter_by(card_number=card_number).first()

#         if not card:
#             return jsonify({'error': 'Card not found'}), 404

#         # Check if the current balance is greater than zero (optional)
#         if card.balance < 0:
#             return jsonify({'error': 'You can only top up if your balance is greater than zero'}), 400

#         # Perform the top-up
#         card.balance += topup_amount  # Add the top-up amount to the card balance
#         db.session.commit()  # Save changes to the database

#         # Return success response with updated balance
#         return jsonify({'message': 'Top-up successful', 'new_balance': card.balance}), 200

#     except Exception as e:
#         return jsonify({'error': str(e)}), 500
@csrf.exempt
@app.route('/topup', methods=['POST'])
def topup():
    try:
        data = request.get_json()
        card_number = data.get('card_number')
        topup_amount = data.get('amount')

        if not card_number or not topup_amount:
            return jsonify({'error': 'Card number and amount are required'}), 400

        if topup_amount <= 0:
            return jsonify({'error': 'Top-up amount must be greater than zero'}), 400

        card = Card.query.filter_by(card_number=card_number).first()

        if not card:
            return jsonify({'error': 'Card not found'}), 404

        card.balance += topup_amount
        db.session.commit()

        return jsonify({'message': 'Top-up successful', 'new_balance': card.balance}), 200

    except Exception as e:
        return jsonify({'error': str(e)}), 500

@app.route('/transfers')
def transfers():
    # Fetch all transfer records from the database
    transfers = Transfer.query.order_by(Transfer.date.desc()).all()
    return render_template('transfer_balance.html', transfers=transfers)

@app.route("/calculate_expenses", methods=['GET', 'POST'])
def calculate_expenses():
    # Ensure user is logged in
    if 'user_id' not in session:
        flash('You need to log in first!', 'danger')
        return redirect(url_for('login'))
    # Get the current user's ID
    user_id = session['user_id']
    # Query the database to get all transfers made by the user
    total_expenses = db.session.query(db.func.sum(Transfer.amount)).filter(Transfer.sender_card_number == user_id).scalar()
    if total_expenses is None:
        total_expenses = 0.0  # Handle case where no transfers exist for the user
    return render_template('calculate_expenses.html', total_expenses=total_expenses)


@app.route('/logout')
def logout():
    session.pop('username', None)
    session.pop('role', None)
    session.pop('user_id', None)
    flash('You have been logged out.', 'success')
    return redirect(url_for('home'))

# Run the application
@app.route('/monthly_transactions')
def monthly_transactions():
    if 'user_id' not in session:
        flash('You need to log in first!', 'danger')
        return redirect(url_for('login'))

    user_id = session['user_id']

    # Query to get monthly transactions for each card
    transactions = db.session.query(
        Transfer.sender_card_number,
        func.strftime('%Y-%m', Transfer.date).label('month'),
        func.sum(Transfer.amount).label('total_amount')
    ).filter(Transfer.sender_card_number == user_id)\
     .group_by(Transfer.sender_card_number, func.strftime('%Y-%m', Transfer.date))\
     .order_by(Transfer.sender_card_number, func.strftime('%Y-%m', Transfer.date))\
     .all()

    # Process the data for the frontend
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
def predict():
    try:
        # Extract form data
        distance = float(request.form['distance'])
        fuel_price = float(request.form['fuel_price'])
        trips_per_day = int(request.form['trips_per_day'])
        peak_off_peak = int(request.form['peak_off_peak'])

        # Prepare input DataFrame
        inputs = {
            'Distance': distance,
            'Fuel_Price': fuel_price,
            'Trips_Per_Day': trips_per_day,
            'Peak/Off-Peak': peak_off_peak
        }
        inputs_df = pd.DataFrame([inputs])

        # Forecast the cost
        forecast_steps = 1
        forecast = model.forecast(steps=forecast_steps)

        # Pass the result to the result template
        return render_template('result.html', forecasted_cost=forecast[0])

    except Exception as e:
        return jsonify({'error': str(e)}), 400
    
@app.route('/x')
def x():
    return render_template('index.html')
# Run the application

@app.route('/predictx', methods=['POST'])
def predictx():
    try:
        # Get data from the POST request
        data = request.get_json()
        print("Received data:", data)  # Debugging line
        inputs = data['inputs']
        inputs_df = pd.DataFrame(inputs)
        forecast_steps = 1
        forecast = model.forecast(steps=forecast_steps)
        return jsonify({'forecasted_cost': forecast[0]})
    except Exception as e:
        print("Error:", str(e))  # Debugging line
        return jsonify({'error': str(e)}), 400

@app.route('/card-details', methods=['POST'])
def card_details():
    try:
        # Get card number from the request
        data = request.get_json()
        card_number = data.get('card_number')

        if not card_number:
            return jsonify({'error': 'Card number is required'}), 400

        # SQL query to fetch card details and monthly transactions
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

        # Execute the query
        result = db.session.execute(query, {
            'card_number': card_number,
            'current_date': datetime.now().strftime('%Y-%m-%d')
        }).fetchone()

        if not result:
            return jsonify({'error': 'Card not found'}), 404

        # Convert result to a dictionary
        card_details = {
            'card_number': result.card_number,
            'cardholder_name': result.cardholder_name,
          
            'balance': result.balance,
            'total_monthly_transactions': result.total_monthly_transactions
        }

        return jsonify(card_details)

    except Exception as e:
        return jsonify({'error': str(e)}), 500


@app.route('/predict-cost', methods=['POST'])
def predict_cost():
    try:
        # Get card number from the request
        data = request.get_json()
        card_number = data.get('card_number')

        if not card_number:
            return jsonify({'error': 'Card number is required'}), 400

        # SQL query to fetch total monthly transactions
        query = text("""
            SELECT 
                IFNULL(SUM(t.amount), 0) AS total_monthly_transactions
            FROM "transaction" t 
            WHERE t.card_number = :card_number 
              AND strftime('%Y-%m', t.timestamp) = strftime('%Y-%m', :current_date)
        """)

        # Execute the query
        result = db.session.execute(query, {
            'card_number': card_number,
            'current_date': datetime.now().strftime('%Y-%m-%d')
        }).fetchone()

        if not result:
            return jsonify({'error': 'No transactions found for this card'}), 404

        # Extract total_monthly_transactions
        total_monthly_transactions = result.total_monthly_transactions

        # Use the ARIMA model to predict based on total_monthly_transactions
        # Preprocess the input as needed by the model
        forecast = model.forecast(steps=1, exog=[[total_monthly_transactions]])

        # Return the predicted cost
        return jsonify({
            'card_number': card_number,
            'total_monthly_transactions': total_monthly_transactions,
            'forecasted_cost': forecast[0]
        })

    except Exception as e:
        return jsonify({'error': str(e)}), 500

@app.route('/card-and-predict', methods=['POST'])
def card_and_predict():
    try:
        # Get card number from the request
        data = request.get_json()
        card_number = data.get('card_number')

        if not card_number:
            return jsonify({'error': 'Card number is required'}), 400

        # SQL query to fetch card details and total monthly transactions
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

        # Execute the query
        result = db.session.execute(query, {
            'card_number': card_number,
            'current_date': datetime.now().strftime('%Y-%m-%d')
        }).fetchone()

        if not result:
            return jsonify({'error': 'Card not found'}), 404

        # Extract details
        card_details = {
            'card_number': result.card_number,
            'cardholder_name': result.cardholder_name,
           
            'balance': result.balance,
            'total_monthly_transactions': result.total_monthly_transactions
        }

        # Use the ARIMA model to predict based on total_monthly_transactions
        forecast = model.forecast(steps=1, exog=[[result.total_monthly_transactions]])

        # Add prediction to the response
        card_details['predicted_cost'] = forecast[0]

        return jsonify(card_details)

    except Exception as e:
        return jsonify({'error': str(e)}), 500   
@app.route('/card-details-ui')
def card_details_ui():
    return render_template('card_details.html')

@app.route('/capredict', methods=['GET'])
def capredict():
    try:
        # SQL query to fetch card details and total monthly transactions for all cards
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

        # Execute the query
        results = db.session.execute(query, {
            'current_date': datetime.now().strftime('%Y-%m-%d')
        }).fetchall()

        if not results:
            return jsonify({'error': 'No cards found'}), 404

        # Prepare the response data
        all_card_details = []
        for result in results:
            # Extract details
            card_details = {
                'card_number': result.card_number,
                'cardholder_name': result.cardholder_name,
                'balance': result.balance,
                'total_monthly_transactions': result.total_monthly_transactions
            }

            # Use the ARIMA model to predict based on total_monthly_transactions
            forecast = model.forecast(steps=1, exog=[[result.total_monthly_transactions]])
            card_details['predicted_cost'] = forecast[0]

            all_card_details.append(card_details)

        return jsonify(all_card_details)

    except Exception as e:
        return jsonify({'error': str(e)}), 500

@app.route('/cardpredict/<card_number>', methods=['GET'])
def cardpredict(card_number):
    try:
        # SQL query to fetch card details and total monthly transactions for the given card
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

        # Execute the query with the card_number and current_date
        result = db.session.execute(query, {
            'card_number': card_number,
            'current_date': datetime.now().strftime('%Y-%m-%d')
        }).fetchone()

        if not result:
            return jsonify({'error': 'Card not found'}), 404

        # Extract details
        card_details = {
            'card_number': result.card_number,
            'cardholder_name': result.cardholder_name,
            'balance': result.balance,
            'total_monthly_transactions': result.total_monthly_transactions
        }

        # Use the ARIMA model to predict based on total_monthly_transactions
        forecast = model.forecast(steps=1, exog=[[result.total_monthly_transactions]])
        card_details['predicted_cost'] = forecast[0]

        return jsonify(card_details)

    except Exception as e:
        return jsonify({'error': str(e)}), 500

@app.route('/view-cards')
def view_cards():
    return render_template('card_and_predict.html')

@app.route('/manage_users')
@role_required('admin')
def manage_users():
    users = User.query.all()
    transfers = Transfer.query.order_by(Transfer.date.desc()).all()
    return render_template('manage_users.html', users=users,transfers=transfers)


# @app.route('/admin/view_users', methods=['GET'])
# @role_required('admin')
# def view_users_and_cards():
#     try:
#         # Fetch all users and their associated cards
#         users_with_cards = db.session.query(User, Card).outerjoin(Card, User.id == Card.user_id).all()

#         # Group cards by user
#         users_data = {}
#         for user, card in users_with_cards:
#             if user.id not in users_data:
#                 users_data[user.id] = {
#                     'username': user.username,
#                     'role': user.role,
#                     'cards': []
#                 }
#             if card:
#                 users_data[user.id]['cards'].append({
#                     'card_number': card.card_number,
#                     'cardholder_name': card.cardholder_name,
#                     'balance': card.balance,
#                     'expiry_date': card.expiry_date
#                 })

#         return render_template('view_users.html', users=users_data.values())

#     except Exception as e:
#         app.logger.error(f"Error loading users and cards: {e}")
#         flash('An error occurred while loading users and cards.', 'danger')
#         return redirect(url_for('admin_dashboard'))
@app.route('/admin/view_users', methods=['GET'])
@role_required('admin')
def view_users_and_cards():
    try:
        # Fetch all users and their associated cards
        users_with_cards = db.session.query(User, Card).outerjoin(Card, User.id == Card.user_id).all()
        # Group cards by user and calculate predictions
        users_data = {}
        for user, card in users_with_cards:
            if user.id not in users_data:
                users_data[user.id] = {
                    'username': user.username,
                    'role': user.role,
                    'cards': []
                }
            if card:
                # Fetch total monthly transactions for the card
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

                # Predict next month's cost
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
        app.logger.error(f"Error loading users and cards: {e}")
        flash('An error occurred while loading users and cards.', 'danger')
        return redirect(url_for('admin_dashboard'))


@app.route('/admin/admanage_cards', methods=['GET', 'POST'])
@role_required('admin')
def admanage_cards():
    try:
        search_query = request.args.get('search', '')

        # Filter cards based on search query
        if search_query:
            cards = Card.query.filter(
                db.or_(
                    Card.card_number.like(f"%{search_query}%"),
                    Card.cardholder_name.like(f"%{search_query}%")
                )
            ).all()
        else:
            # Fetch all cards if no search query is provided
            cards = Card.query.all()

        # Add prediction for each card
        cards_with_predictions = []
        for card in cards:
            # Fetch total monthly transactions
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

            # Predict next month's cost
            predicted_cost = model.forecast(steps=1, exog=[[total_monthly_transactions]])[0]

            # Append to card details
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
        app.logger.error(f"Error loading cards: {e}")
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
        flash(f"Card '{card.card_number}' has been deleted successfully.", 'success')
    except Exception as e:
        app.logger.error(f"Error deleting card: {e}")
        flash('An error occurred while deleting the card.', 'danger')
    return redirect(url_for('admanage_cards'))


@app.route('/admin/assign_card', methods=['GET', 'POST'])
@role_required('admin')
def assign_card():
    form = AssignCardForm()
    # Populate user dropdown with existing users
    form.user_id.choices = [(user.id, user.username) for user in User.query.all()]
    if form.validate_on_submit():
        user_id = form.user_id.data

        # Create a new card and assign it to the selected user
        new_card = Card(
            card_number=form.card_number.data,
            cardholder_name=form.cardholder_name.data,
            balance=form.balance.data,
            expiry_date=form.expiry_date.data,
            user_id=user_id  # Assigning to user
        )

        db.session.add(new_card)
        db.session.commit()

        flash(f'Card assigned to {User.query.get(user_id).username} successfully!', 'success')
        return redirect(url_for('assign_card'))

    return render_template('assign_card.html', form=form)



# @app.route('/')
# def index():
#     transfers = Transfer.query.order_by(Transfer.date.desc()).all()
#     return render_template('index.html', transfers=transfers)

@app.route('/create', methods=['GET', 'POST'])
@role_required('admin')
def create_transfer():
    form = TransferForm()
    if form.validate_on_submit():
        new_transfer = Transfer(
            sender_card_number=form.sender_card_number.data,
            receiver_card_number=form.receiver_card_number.data,
            amount=form.amount.data
        )
        db.session.add(new_transfer)
        db.session.commit()
        return redirect(url_for('login'))
    return render_template('create_transfer.html', form=form)

@app.route('/transfer/<int:transfer_id>')
@role_required('admin')
def transfer_details(transfer_id):
    transfer = Transfer.query.get_or_404(transfer_id)
    return render_template('transfer_details.html', transfer=transfer)

# def send_user_report(user_id, recipient_email):
#     with app.app_context():
#         user = User.query.get(user_id)
#         if not user:
#             print(f"User {user_id} not found.")
#             return "User not found"

#         cards = Card.query.filter_by(user_id=user.id).all()
#         transactions = Transaction.query.filter_by(user_id=user.id).all()
#         files = FileUpload.query.filter_by(username=user.username).all()

#         message_body = f"A NOVEL AI_IoT BASED TAP AND GO CARD FOR INTELLIGENT SYSTEM AND MANAGEMENT  {user.username}:\n\n"
#         message_body += f"Username: {user.username}\n"
#         message_body += f"Role: {user.role}\n\n"

#         message_body += "Cards:\n"
#         for card in cards:
#             message_body += f"  Card Number: {card.card_number}\n"
#             message_body += f"  Cardholder Name: {card.cardholder_name}\n"
#             message_body += f"  Balance: {card.balance}\n"
#             message_body += f"  Expiry Date: {card.expiry_date}\n\n"

#         message_body += "Transactions:\n"
#         for transaction in transactions:
#             message_body += f"  Amount: {transaction.amount}\n"
#             message_body += f"  Type: {transaction.transaction_type}\n"
#             message_body += f"  Card Number: {transaction.card_number}\n"
#             message_body += f"  Timestamp: {transaction.timestamp}\n\n"

#         message_body += "Uploaded Files:\n"
#         for file in files:
#             message_body += f"  Filename: {file.filename}\n"
#             message_body += f"  Description: {file.description}\n\n"

#         msg = Message("User Report", sender=app.config['MAIL_USERNAME'], recipients=[recipient_email])
#         msg.body = message_body

#         try:
#             mail.send(msg)
#             print(f"Email sent successfully to {recipient_email} for user {user_id}")
#             return "Email sent successfully"
#         except Exception as e:
#             print(f"Error sending email: {e}")
#             return f"Error sending email: {e}"

# def send_reports_periodically(user_id, recipient_email, interval_seconds=1080): #3 minutes = 180 seconds
#     while True:
#         send_user_report(user_id, recipient_email)
#         time.sleep(interval_seconds)

# def start_all_periodic_reports():
#     with app.app_context():
#         users = User.query.all()
#         for user in users:
#             recipient_email = f"{user.username}" #Replace with actual email format
#             thread = threading.Thread(target=send_reports_periodically, args=(user.id, recipient_email))
#             thread.daemon = True
#             thread.start()
#             print(f"Started periodic reports for user {user.id} to {recipient_email}")
from email_validator import validate_email, EmailNotValidError  # Add for email validation
import re

def send_user_report(user_id, recipient_email):
    with app.app_context():
        user = User.query.get(user_id)
        if not user:
            print(f"User {user_id} not found.")
            return "User not found"

        cards = Card.query.filter_by(user_id=user.id).all()
        transactions = Transaction.query.filter_by(user_id=user.id).all()
        files = FileUpload.query.filter_by(username=user.username).all()

        message_body = f"A NOVEL AI_IoT BASED TAP AND GO CARD FOR INTELLIGENT SYSTEM AND MANAGEMENT  {user.username}:\n\n"
        message_body += f"Username: {user.username}\n"
        message_body += f"Role: {user.role}\n\n"

        message_body += "Cards:\n"
        for card in cards:
            message_body += f"  Card Number: {card.card_number}\n"
            message_body += f"  Cardholder Name: {card.cardholder_name}\n"
            message_body += f"  Balance: {card.balance}\n"
            message_body += f"  Expiry Date: {card.expiry_date}\n\n"

        message_body += "Transactions:\n"
        for transaction in transactions:
            message_body += f"  Amount: {transaction.amount}\n"
            message_body += f"  Type: {transaction.transaction_type}\n"
            message_body += f"  Card Number: {transaction.card_number}\n"
            message_body += f"  Timestamp: {transaction.timestamp}\n\n"

        message_body += "Uploaded Files:\n"
        for file in files:
            message_body += f"  Filename: {file.filename}\n"
            message_body += f"  Description: {file.description}\n\n"

        msg = Message("User Report", sender=app.config['MAIL_USERNAME'], recipients=[recipient_email])
        msg.body = message_body

        try:
            mail.send(msg)
            print(f"Email sent successfully to {recipient_email} for user {user_id}")
            return "Email sent successfully"
        except Exception as e:
            print(f"Error sending email: {e}")
            return f"Error sending email: {e}"

@app.route('/send-report', methods=['POST'])
@role_required('client')
def send_report_route():
    if 'user_id' not in session or 'username' not in session:
        flash('You need to log in first!', 'danger')
        return jsonify({"error": "Not logged in"}), 401

    user_id = session['user_id']
    # Sanitize username to create a valid email local part
    username = session['username']
    sanitized_username = re.sub(r'[^a-zA-Z0-9.!#$%&\'*+/=?^_`{|}~-]', '', username)
    recipient_email = f"{sanitized_username}@vrt.rw"  # Use your domain

    # Validate email format
    try:
        validate_email(recipient_email, check_deliverability=False)
    except EmailNotValidError as e:
        flash('Invalid email address format. Please contact support.', 'danger')
        return jsonify({"error": f"Invalid email address: {str(e)}"}), 400

    result = send_user_report(user_id, recipient_email)
    if result == "Email sent successfully":
        flash('Report sent successfully!', 'success')
        return jsonify({"message": result}), 200
    elif result == "User not found":
        flash('User not found.', 'danger')
        return jsonify({"error": result}), 404
    else:
        flash('Error sending report.', 'danger')
        return jsonify({"error": result}), 500


if __name__ == '__main__':
    with app.app_context():
        db.create_all()  # Create database tables
    # threading.Thread(target=start_all_periodic_reports).start()
    app.run(host='0.0.0.0', port=5000, debug=False)
