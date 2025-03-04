# forms.py

from flask_wtf import FlaskForm
from wtforms import StringField, PasswordField, SelectField, FileField, TextAreaField, SubmitField
from wtforms.validators import DataRequired

class RegistrationForm(FlaskForm):
    username = StringField('Username', validators=[DataRequired()])
    password = PasswordField('Password', validators=[DataRequired()])
    role = SelectField('Role', choices=[('admin', 'Admin'), ('vender_machine', 'vender_machine'), ('client', 'client')], validators=[DataRequired()])
    submit = SubmitField('Register')

class LoginForm(FlaskForm):
    username = StringField('Username', validators=[DataRequired()])
    password = PasswordField('Password', validators=[DataRequired()])
    submit = SubmitField('Login')

class FileUploadForm(FlaskForm):
    file = FileField('Upload PDF', validators=[DataRequired()])
    description = TextAreaField('Description', validators=[DataRequired()])
    submit = SubmitField('Upload')
class AssignCardForm(FlaskForm):
    user_id = SelectField('Assign to User', coerce=int, validators=[DataRequired()])
    card_number = StringField('Card Number', validators=[DataRequired(), Length(min=13, max=19)])
    cardholder_name = StringField('Cardholder Name', validators=[DataRequired(), Length(min=2, max=50)])
    balance = FloatField('Initial Balance', validators=[DataRequired()])
    expiry_date = DateField('Expiry Date', format='%Y-%m-%d', validators=[DataRequired()])
    submit = SubmitField('Assign Card')
