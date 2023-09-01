from flask import Flask, render_template, redirect, url_for
from flask_sqlalchemy import SQLAlchemy
from flask_login import UserMixin, login_user, LoginManager, login_required, logout_user

from flask_wtf import FlaskForm
from wtforms import StringField, PasswordField, SubmitField
from wtforms.validators import InputRequired, Length, ValidationError

from flask_bcrypt import Bcrypt
from integritychain import Integrity, IntegrityChain

app = Flask(__name__)
app.config['SECRET_KEY'] = 'secret-key-123'
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///database.db'

db = SQLAlchemy()
db.init_app(app)
bcrypt = Bcrypt(app)

login_manager = LoginManager()
login_manager.init_app(app)
login_manager.login_view = 'login'

## Models ## 

class User(db.Model, UserMixin):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(20), nullable=False, unique=True)
    password = db.Column(db.String(80), nullable=False)

class Blockchain(db.Model):
    number = db.Column(db.Integer, primary_key=True)
    hash = db.Column(db.String(80), nullable=False)
    previous_hash = db.Column(db.String(80), nullable=False)
    data = db.Column(db.String(80), nullable=False)
    nonce = db.Column(db.Integer)

@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))

## Forms ## 

class RegisterForm(FlaskForm):
    username = StringField(validators=[InputRequired(), Length(min=4, max=20)], render_kw={'placeholder': "Username"})
    password = PasswordField(validators=[InputRequired(), Length(min=4, max=20)], render_kw={'placeholder': "Password"})
    submit = SubmitField("Register")

    def validate_username(self, username):
        existing_user_username = User.query.filter_by(
            username=username.data).first()
        if existing_user_username:
            raise ValidationError(
                'That username already exists. Please choose a different one.')

class LoginForm(FlaskForm):
    username = StringField(validators=[
                           InputRequired(), Length(min=4, max=20)], render_kw={"placeholder": "Username"})

    password = PasswordField(validators=[
                             InputRequired(), Length(min=8, max=20)], render_kw={"placeholder": "Password"})

    submit = SubmitField('Login')

## DB Tools ##

def get_blockchain():
    integritychain = IntegrityChain()
    blockchain_sql = Blockchain.query.all()
    for block in blockchain_sql:
        integritychain.add(Integrity(number=int(block.number), 
                                     previous_hash=block.previous_hash, 
                                     data=block.data, 
                                     nonce=block.nonce))
        
    return integritychain


def sync_blockchain(integritychain):
    blockchain_sql = Blockchain.query.delete()

    for integrity in integritychain.chain:
        block = Blockchain(number=int(integrity.number), 
                   hash=integrity.hash(), 
                   previous_hash=integrity.previous_hash, 
                   data=integrity.data, 
                   nonce=integrity.nonce)

        db.session.add(block)
    
    db.session.commit()


# def test_blockchain():
#     blockchain_sql = Blockchain.query.delete()
#     db.session.commit()
#     # blockchain = IntegrityChain()
#     # database = ["First Project", "AI Projet", "ML Project", "END"]
    
#     # num = 0
#     # for data in database:
#     #     num += 1
#     #     blockchain.mine(Integrity(data=data, number=num))
    
#     # sync_blockchain(blockchain)

## Routes ##

@app.route('/')
def index():
    return render_template('index.html')

@app.route('/dashboard', methods=["GET", "POST"])
@login_required
def dashboard():
    return render_template('dashboard.html')

@app.route('/login', methods=["GET", "POST"])
def login():
    form = LoginForm()

    if form.validate_on_submit():
        user = User.query.filter_by(username=form.username.data).first()
        if user:
            if bcrypt.check_password_hash(user.password, form.password.data):
                login_user(user)
                return redirect(url_for('dashboard'))
            
    return render_template('login.html', form=form)

@app.route('/logout', methods=['GET', 'POST'])
@login_required
def logout():
    logout_user()
    return redirect(url_for('login'))

@app.route('/register', methods=["GET", "POST"])
def register():
    form = RegisterForm()

    if form.validate_on_submit():
        hashed_password = bcrypt.generate_password_hash(form.password.data)
        new_user = User(username=form.username.data, password=hashed_password)
        db.session.add(new_user)
        db.session.commit()
        return redirect(url_for('login'))
    
    return render_template('register.html', form=form)

if __name__ == "__main__":
    app.run(debug=True)