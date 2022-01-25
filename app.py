
from enum import unique
from flask import Flask,render_template,redirect,url_for,flash,request,session
from flask_sqlalchemy import SQLAlchemy
from flask_login import LoginManager,UserMixin, login_required, login_user,logout_user,current_user
from werkzeug.security import generate_password_hash, check_password_hash
from flask_wtf import FlaskForm
from wtforms import StringField,PasswordField,SubmitField,BooleanField
from wtforms.validators import DataRequired,Email,EqualTo
import os

SECRET_KEY = os.urandom(32)

app=Flask('__name__')
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///db.sqlite'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
app.config['SECRET_KEY'] = SECRET_KEY
db=SQLAlchemy(app)

login_manager=LoginManager()
login_manager.init_app(app)

# Models

class User(UserMixin,db.Model):
    id=db.Column(db.Integer,primary_key=True)
    username=db.Column(db.String(150),unique=True)
    email=db.Column(db.String(100),unique=True)
    hashed_password=db.Column(db.String(150))

    def set_password(self,password):
        self.hashed_password=generate_password_hash(password)

    def check_password(self,password):
        return check_password_hash(self.hashed_password,password)



class Todo(db.Model):
    id=db.Column(db.Integer,primary_key=True)
    user_id=db.Column(db.Integer,db.ForeignKey('user.id'))
    title=db.Column(db.String(100))
    complete=db.Column(db.Boolean)


# Forms

class RegistrationForm(FlaskForm):
    username=StringField('Username',validators=[DataRequired()])
    email=StringField('Email',validators=[DataRequired(),Email()])
    password1=StringField('Password',validators=[DataRequired()])
    password2=StringField('Confirm Password',validators=[DataRequired(),EqualTo('password1')])
    submit=SubmitField('Register')

class LoginForm(FlaskForm):
    email=StringField('Email',validators=[DataRequired(),Email()])
    password=StringField('Password',validators=[DataRequired()])
    submit=SubmitField('Login')


@login_manager.user_loader
def load_user(user_id):
    return User.query.get(user_id)

@app.route('/')
def index():
    return render_template('index.html')

@app.route('/register/',methods=["POST","GET"])
def register():
    form=RegistrationForm()
    if form.validate_on_submit():
        user=User(username=form.username.data,email=form.email.data)
        user.set_password(form.password1.data)
        db.session.add(user)
        db.session.commit()
        return redirect (url_for('login'))
    return render_template('register.html',form=form)


@app.route('/login/',methods=["POST","GET"])
def login():
    form=LoginForm()
    if form.validate_on_submit():
        user=User.query.filter_by(email=form.email.data).first()
        if user is not None and user.check_password(form.password.data):
            login_user(user)
            return redirect(url_for('home'))
        flash('Invalid userame or password')
    return render_template('login.html',form=form)


@app.route('/home')
def home():
    todo_list=Todo.query.filter_by(user_id=current_user.id)
    return render_template('home.html',todo_list=todo_list,c_user=current_user)


@app.route("/logout")
@login_required
def logout():
    logout_user()
    return redirect(url_for('home'))

@app.route('/add',methods=["POST"])
@login_required
def add():
    title=request.form.get("title")
    user_id = current_user.id
    todo_item=Todo(user_id=user_id,title=title,complete=False)
    db.session.add(todo_item)
    db.session.commit()
    return redirect(url_for("home"))

@app.route('/update/<int:todoId>')
def update(todoId):
    todo_item=Todo.query.filter_by(id=todoId).first()
    todo_item.complete=not todo_item.complete
    db.session.commit()
    return redirect(url_for("home"))


@app.route('/delete/<int:todoId>')
def delete(todoId):
    todo_item=Todo.query.filter_by(id=todoId).first()
    db.session.delete(todo_item)
    db.session.commit()
    return redirect(url_for("home"))

    





if __name__=='__main__':
    db.create_all()
    # new_todo=Todo(title='Todo 1',complete=True)
    # db.session.add(new_todo)
    # db.session.commit()
    app.run()