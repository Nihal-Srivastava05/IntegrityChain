from flask import Flask, render_template, redirect, url_for, request, flash
from flask_sqlalchemy import SQLAlchemy
from flask_migrate import Migrate
from flask_login import UserMixin, login_user, LoginManager, login_required, logout_user, current_user

from flask_wtf import FlaskForm
from wtforms import StringField, PasswordField, SubmitField, DecimalRangeField, HiddenField
from wtforms.validators import InputRequired, Length, ValidationError

from flask_bcrypt import Bcrypt
from integritychain import Integrity, IntegrityChain

from sentence_transformers import SentenceTransformer
from sklearn.metrics.pairwise import cosine_similarity

import datetime
import decimal

app = Flask(__name__)
app.config['SECRET_KEY'] = 'secret-key-123'
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///database.db'

db = SQLAlchemy()
db.init_app(app)
bcrypt = Bcrypt(app)

login_manager = LoginManager()
login_manager.init_app(app)
login_manager.login_view = 'login'

migrate = Migrate(app, db)

bert_model = SentenceTransformer('distilbert-base-nli-mean-tokens')

class ProjectExistException(Exception): pass

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

class Votes(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    title = db.Column(db.String(50), nullable=False)
    total_sum = db.Column(db.Float)
    number_votes = db.Column(db.Integer)

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

class FindProjectForm(FlaskForm):
    query = StringField("Search", validators=[InputRequired(), Length(min=5, max=50)])
    submit1 = SubmitField("Search")

class VoteProjectForm(FlaskForm):
    vote = DecimalRangeField('Vote', default=0)
    title = HiddenField("Title")
    submit2 = SubmitField("Submit")

class AddProjectForm(FlaskForm):
    title = StringField("Title", validators=[InputRequired(), Length(min=5, max=30)])
    description = StringField("Title", validators=[InputRequired(), Length(min=5, max=200)])
    submit = SubmitField('Add')

## DB Tools ##

def add_project(author, title, description):
    blockchain = get_blockchain()
    if not does_project_exists(blockchain, title):
        raise ProjectExistException("Project already exist")
    
    number = len(blockchain.chain) + 1
    timestamp = datetime.datetime.now().isoformat()
    data = "%s->%s->%s->%s" %(author, title, description, timestamp)
    
    blockchain.mine(Integrity(number=number, data=data))
    sync_blockchain(blockchain)

def does_project_exists(blockchain, title):
    encoded_title = bert_model.encode([title])
    for block in blockchain.chain:
        data = block.data.split("->") # author->title->description
        encoded = bert_model.encode([data[1]])
        sim = cosine_similarity(encoded_title, encoded)
        if sim > 0.70:
            return False
        
    return True

def get_blockchain():
    integritychain = IntegrityChain(chain=[])
    blockchain_sql = Blockchain.query.all()
    for block in blockchain_sql:
        integritychain.add(Integrity(number=int(block.number), 
                                     previous_hash=block.previous_hash, 
                                     data=block.data, 
                                     nonce=block.nonce))
        
    return integritychain

def sync_blockchain(integritychain):
    blockchain_sql = Blockchain.query.delete()
    db.session.commit()

    for integrity in integritychain.chain:
        block = Blockchain(number=int(integrity.number), 
                   hash=integrity.hash(), 
                   previous_hash=integrity.previous_hash, 
                   data=integrity.data, 
                   nonce=integrity.nonce)

        db.session.add(block)
    
    db.session.commit()

@app.route('/')
def index():
    return render_template('index.html')

@app.route('/transaction', methods=["GET", "POST"])
@login_required
def transaction():
    form = AddProjectForm()
    blockchain = get_blockchain()
    projects = []
    for block in blockchain.chain:
        data = block.data.split("->")
        projects.append(data)
    
    if form.validate_on_submit():
        user_id = current_user.get_id()
        author = User.query.filter_by(id=user_id).first().username
        title = form.title.data
        description = form.description.data
        try:
            add_project(author=author, title=title, description=description)
            flash("Project added", 'success')
        except Exception as e:
            flash(str(e), 'danger')
            
        return redirect(url_for('transaction'))

    return render_template('transaction.html', form=form, projects=projects)

@app.route('/dashboard', methods=["GET", "POST"])
@login_required
def dashboard():
    blockchain = get_blockchain()
    projects = []
    user_id = current_user.get_id()
    user_name = User.query.filter_by(id=user_id).first().username
    for block in blockchain.chain:
        data = block.data.split("->")
        if data[0] == user_name:
            projects.append(data)
        
    form = FindProjectForm()
    vote_form = VoteProjectForm()

    search_results = []
    if form.submit1.data and form.validate():
        query = form.query.data
        blockchain = get_blockchain()
        encoded_title = bert_model.encode([query])
        for block in blockchain.chain:
            data = block.data.split("->")
            encoded = bert_model.encode([data[1]])
            sim = cosine_similarity(encoded_title, encoded)
            if sim > 0.60:
                votes = db.session.query(Votes).filter_by(title=data[1]).first()
                score = 0
                if votes is not None:
                    score = votes.total_sum / votes.number_votes
                search_results.append(data + [score])

    if vote_form.submit2.data:
        title = vote_form.title.data
        vote = vote_form.vote.data

        res = db.session.query(Votes).filter_by(title=title).first()
        if res is None:
            new_vote = Votes(title=title, total_sum=vote, number_votes=1)
            db.session.add(new_vote)
        else:
            res.total_sum += float(vote)
            res.number_votes += 1
        
        db.session.commit()

    # if vote_form.submit2.data and vote_form.validate():
    #     title = vote_form.title.data
    #     vote = vote_form.vote.data
    #     print(title, vote)

    return render_template('dashboard.html', form=form, vote_form=vote_form, projects=projects, search_results=search_results)

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