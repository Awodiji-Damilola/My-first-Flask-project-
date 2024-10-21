from datetime import datetime
import phonenumbers
import os
from flask import Flask, session, render_template, redirect, url_for, flash
from flask_sqlalchemy import SQLAlchemy
from flask_migrate import Migrate
from flask_bootstrap import Bootstrap
from flask_moment import Moment
from flask_wtf import FlaskForm
from wtforms import StringField, SubmitField, PasswordField
from wtforms.validators import DataRequired, Email, EqualTo, Length, ValidationError
from werkzeug.security import generate_password_hash, check_password_hash
import re

app = Flask(__name__)
app.config['SECRET_KEY'] = 'hard to reach'

basedir = os.path.abspath(os.path.dirname(__file__))
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///' + os.path.join(basedir, 'data.sqlite')
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False

bootstrap = Bootstrap(app)
moment = Moment(app)
db = SQLAlchemy(app)
migrate = Migrate(app, db)

class User(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(64), nullable=False)
    username = db.Column(db.String(64), unique=True, nullable=False)
    email = db.Column(db.String(120), unique=True, nullable=False)
    password = db.Column(db.String(128), nullable=False)
    phone_number = db.Column(db.String(15), nullable=False, default='N/A')
    date_joined = db.Column(db.String(10), nullable=False)

# Generate unique username
def generate_unique_username(first_name, last_name):
    base_username = first_name[0].lower() + '_' + last_name[:4].lower()
    existing_user = User.query.filter_by(username=base_username).first()
    if not existing_user:
        return base_username
    else:
        count = 1
        while True:
            unique_username = f"{base_username}{count}"
            existing_user = User.query.filter_by(username=unique_username).first()
            if not existing_user:
                return unique_username
            count += 1

# Custom Phone Validator
def validate_phone(form, field):
    phone_number = field.data

    try:
        parsed_number = phonenumbers.parse(phone_number, None)
        if not phonenumbers.is_valid_number(parsed_number):
            raise ValidationError("Invalid phone number for the selected country")
    except phonenumbers.phonenumberutil.NumberParseException:
        raise ValidationError("Invalid phone number format")

# Custom password validator function
def password_complexity_check(form, field):
    password = field.data
    if not re.search(r'[A-Z]', password):
        raise ValidationError('Password must contain at least one uppercase letter.')
    if not re.search(r'[a-z]', password):
        raise ValidationError('Password must contain at least one lowercase letter.')
    if not re.search(r'[0-9]', password):
        raise ValidationError('Password must contain at least one number.')
    if not re.search(r'[!@#$%^&*(),.?":{}|<>]', password):
        raise ValidationError('Password must contain at least one special character.')

# Login form
class LoginForm(FlaskForm):
    email = StringField('What is your email?', validators=[DataRequired(), Email()])
    password = PasswordField('Your password?', validators=[DataRequired()])
    submit = SubmitField('Login')

# Signup form
class SignupForm(FlaskForm):
    first_name = StringField('First Name', validators=[DataRequired()])
    last_name = StringField('Last Name', validators=[DataRequired()])
    email = StringField('Email', validators=[DataRequired(), Email()])
    password = PasswordField('Password', validators=[DataRequired(), Length(min=6), password_complexity_check])
    confirm_password = PasswordField('Confirm Password', validators=[DataRequired(), EqualTo('password')])
    phone_number = StringField('Phone', validators=[DataRequired(), validate_phone])
    submit = SubmitField('Signup')

class UpdateProfileForm(FlaskForm):
    phone_number = StringField('Phone', validators=[DataRequired(), validate_phone])
    submit = SubmitField('Update')

@app.context_processor
def inject_logged_in_status():
    return dict(session=session)

@app.errorhandler(404)
def page_not_found(e):
    return render_template('404.html', error_message=str(e)), 404

@app.errorhandler(500)
def internal_server_error(e):
    return render_template('500.html', error_message=str(e)), 500

# Routes
@app.route('/')
def index():
    return render_template('index.html', current_time=datetime.utcnow())

@app.route('/dashboard')
def dashboard():
    return render_template('dashboard.html')

@app.route('/login', methods=['GET', 'POST'])
def login():
    if 'logged_in' in session and session['logged_in']:
        return redirect(url_for('dashboard'))

    form = LoginForm()

    if form.validate_on_submit():
        email = form.email.data
        password = form.password.data
        user = User.query.filter_by(email=email).first()

        if user and check_password_hash(user.password, password):
            session['logged_in'] = True
            session['email'] = user.email
            session['name'] = user.name
            session['username'] = user.username
            session['phone_number'] = user.phone_number
            session['date_joined'] = user.date_joined

            if user.phone_number == 'N/A':
                flash('Please update your phone number to continue.', 'warning')
                return redirect(url_for('update_profile'))

            flash(f'Welcome back, {session["name"]}!', 'success')
            return redirect(url_for('dashboard'))
        else:
            flash('Invalid email or password. Please try again', 'danger')

    return render_template('login.html', form=form)

@app.route('/signup', methods=['GET', 'POST'])
def signup():
    if 'logged_in' in session and session['logged_in']:
        return redirect(url_for('dashboard'))

    form = SignupForm()
    if form.validate_on_submit():
        print("Form is valid!")
        email = form.email.data
        existing_user = User.query.filter_by(email=email).first()
        
    

        if existing_user:
            flash('Email already exists. Please use a different email or login.', 'danger')
        else:
            name = form.first_name.data + ' ' + form.last_name.data
            username = generate_unique_username(form.first_name.data, form.last_name.data)
            password = generate_password_hash(form.password.data)
            phone_number = form.phone_number.data

            new_user = User(
                name=name,
                email=email,
                username=username,
                password=password,
                phone_number=phone_number,
                date_joined=datetime.utcnow().strftime('%Y-%m-%d')
            )
            db.session.add(new_user)
            db.session.commit()
            print("Database committed with phone number:", new_user.phone_number)  # Debugging line

            session['logged_in'] = True
            session['email'] = email
            session['name'] = name
            session['username'] = username
            session['phone_number'] = phone_number
            session['date_joined'] = new_user.date_joined

            flash(f'Thank you for signing up, {session["name"]}!', 'success')
            return redirect(url_for('dashboard'))
    else:
            print("Form errors:", form.errors)  # Debugging line

    return render_template('signup.html', form=form, )

@app.route('/update_profile', methods=['GET', 'POST'])
def update_profile():
    if 'logged_in' in session and session['logged_in']:
        form = UpdateProfileForm()

        if form.validate_on_submit():
            print("Form is valid!")  # Debugging line
            user = User.query.filter_by(email=session['email']).first()
            user.phone_number = form.phone_number.data  # Assuming you set this correctly
            db.session.commit()
            print("Database committed with phone number:", user.phone_number)  # Debugging line
            
            session['phone_number'] = user.phone_number
            flash('Your profile has been updated!', 'success')
            return redirect(url_for('dashboard'))
        else:
            print("Form errors:", form.errors)  # Debugging line
        return render_template('update_profile.html', form=form)
    else:
        flash('You need to login first.', 'danger')
        return redirect(url_for('login'))


@app.route('/logout')
def logout():
    session.clear()
    flash('You have been logged out.', 'info')
    return redirect(url_for('login'))

with app.app_context():
    db.create_all()

if __name__ == '__main__':
    app.run(debug=True)
