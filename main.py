from flask import Flask, request, render_template, redirect, url_for, session, flash
from flask_sqlalchemy import SQLAlchemy
from functools import wraps
import os
from datetime import datetime
from flask_wtf import FlaskForm
from flask_wtf.csrf import CSRFError, CSRFProtect
from wtforms import StringField, PasswordField, validators, ValidationError
from flask_bcrypt import generate_password_hash, check_password_hash
from flask_login import LoginManager, current_user, login_user, logout_user, login_required, UserMixin

app = Flask(__name__)
app.config['SQLALCHEMY_DATABASE_URI'] = 'mysql://tester:4153@localhost/test6'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
app.secret_key = os.urandom(24)

#CSRF Protection

@app.errorhandler(CSRFError)
def csrf_error(reason):
    return render_template('400.html', reason=reason), 400

csrf = CSRFProtect(app)
WTF_CSRF_ENABLED = True
WTF_CSRF_FIELD_NAME = "csrf_token"
WTF_CSRF_TIME_LIMIT = 3600
#end

#database handling
db = SQLAlchemy(app) 

class User(UserMixin, db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(length=20), index=True, unique=True)
    password = db.Column(db.VARCHAR(length=257))
    email = db.Column(db.String(length=120), unique=True)
    posts = db.relationship('Post', backref="author", lazy="dynamic")
    #posts is lower case for db relationship to Post

    def __repr__(self):
        return '<User {}>'.format(self.username)
        
class Post(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'))
    #user.id is lower case for foreign key in link to User
    timestamp = db.Column(db.DateTime, index=True, default=datetime.utcnow)
    threadtitle = db.Column(db.String(80), nullable=True)
    threadcontent = db.Column(db.String(3500))
    threadurl = db.Column(db.String(80), nullable=True)

    def __repr__(self):
        return '<Post {}>'.format(self.threadcontent)



#end

#login
login_manager = LoginManager(app)
login_manager.login_view = 'loginpage'
login_manager.session_protection = 'strong'

class LoginForm(FlaskForm):
    def username_check(self, field):
        r = User.query.filter_by(username=self.username.data).first().username
        if r == [] or None:
            raise ValidationError('Invalid Username')

    def password_check(self, field):
        r = check_password_hash(User.query.filter_by(username=self.username.data).first().password, self.password.data)
        if r is False or not True or None:
            raise ValidationError('Invalid Password')

    username = StringField('username', [validators.InputRequired(), username_check])
    password = PasswordField('password', [validators.InputRequired(), password_check])

@login_manager.user_loader
def load_user(user):
    return User.query.get(int(user))

@app.route('/login', methods=['GET', 'POST'])
def loginpage():
    form = LoginForm()

    if current_user.is_authenticated:
        return redirect(url_for('homepage'))
    
    if request.method == 'POST' and form.validate_on_submit():
        user = User.query.filter_by(username=form.username.data).first().id
        load_user(user)
        return redirect(url_for('homepage'))

    return render_template('login.html', form=form)

@app.route('/logout')
@login_required
def logout():
    logout_user()
    return redirect(url_for('homepage'))


#end

#registration
class RegistrationForm(FlaskForm):
    def check_if_email_exist(self, field):
        r = User.query.filter_by(email=self.email.data).all()
        if r != []:
            raise ValidationError('Email already exist')

    def check_if_username_exist(self, username):
        r = User.query.filter_by(username=self.username.data).all()
        if r != []:
            raise ValidationError('Username already exist')
    
    username = StringField("Username", [validators.InputRequired(), validators.Length(min=4, max=20), check_if_username_exist])
    email = StringField("Email", [validators.InputRequired(), validators.Email(), check_if_email_exist])
    password = PasswordField("New Password", [validators.InputRequired(), validators.EqualTo('confirm', message="Passwords must match")])
    confirm = PasswordField("Repeat Password")


@app.route('/register', methods=['GET', 'POST'])
def register():
    form = RegistrationForm()
    if request.method == 'POST' and form.validate_on_submit():
        hashedpass = generate_password_hash(form.password.data)
        user = User(username=form.username.data, password=hashedpass, email=form.email.data)
        db.session.add(user)
        db.session.commit()
        return redirect(url_for('loginpage'))
    return render_template('registration.html', form=form)
#end

#
@app.route('/homepage')
def homepage():
    
    return render_template('homepage.html')

#new thread

#end



if __name__ == '__main__':
    app.run(port=50020, debug=True)