from flask import Flask, render_template, redirect, url_for, request, flash
from flask_bootstrap import Bootstrap
from flask_sqlalchemy import SQLAlchemy
from sqlalchemy.orm import relationship
from werkzeug.security import generate_password_hash, check_password_hash
from flask_login import UserMixin, login_user, LoginManager, login_required, current_user, logout_user


app = Flask(__name__)
app.config['SECRET_KEY'] = 'to-do-list'
Bootstrap(app)

app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///lists.db'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
db = SQLAlchemy(app)
login_manager = LoginManager()
login_manager.init_app(app)


@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))


class User(UserMixin, db.Model):
    __tablename__ = 'users'
    id = db.Column(db.Integer, primary_key=True)
    email = db.Column(db.String(100), unique=True)
    password = db.Column(db.String(100))
    name = db.Column(db.String(100))
    lists = relationship("List", back_populates="user")

db.create_all()


class List(UserMixin, db.Model):
    __tablename__ = "list"
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('users.id'), nullable=False)
    item = db.Column(db.String(250), nullable=False)
    date = db.Column(db.String(250), nullable=False)
    user = relationship("User", back_populates="lists")

db.create_all()


@app.route('/')
def home():
    return render_template('index.html', logged_in=current_user.is_authenticated)


@app.route('/register', methods=['GET', 'POST'])
def register():
    if request.method == 'POST':
        if User.query.filter_by(email=request.form.get('email')).first():
            flash("You've already signed with that email, login instead!")
            return redirect(url_for('login'))

        hashed_and_salted_password = generate_password_hash(
            request.form.get('password'),
            method='pbkdf2:sha256',
            salt_length=8
        )
        new_user = User(
            name=request.form.get('name'),
            email=request.form.get('email'),
            password=hashed_and_salted_password
        )
        db.session.add(new_user)
        db.session.commit()
        login_user(new_user)
        user_name = User.query.get(new_user.id).name
        return redirect(url_for('display', current_user=current_user))
    return render_template("register.html", logged_in=current_user.is_authenticated, current_user=current_user)


@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        email = request.form.get('email')
        password = request.form.get('password')
        user = User.query.filter_by(email=email).first()
        if user:
            if check_password_hash(user.password, password):
                login_user(user)
                return redirect(url_for('display'))
            else:
                flash('Password incorrect, please try again')
                return redirect(url_for('login'))
        else:
            flash('That email does not exist, please try again')
            return redirect(url_for('login'))
    return render_template("login.html", logged_in=current_user.is_authenticated, current_user=current_user)


@app.route('/list', methods=['GET', 'POST'])
@login_required
def lists():
    if request.method == "POST":
        new_list = List(
            item=request.form.get('Task'),
            date=request.form.get('Due Date'),
            user=current_user

        )
        db.session.add(new_list)
        db.session.commit()
        return redirect(url_for('display', current_user=current_user))
    return render_template("list.html", logged_in=True, current_user=current_user)


@login_required
@app.route('/display')
def display():
    all_items = List.query.all()
    return render_template('add.html', logged_in=True, items=all_items, current_user=current_user)


@app.route("/delete/<int:item_id>")
def delete_item(item_id):
    item_to_delete = List.query.get(item_id)
    db.session.delete(item_to_delete)
    db.session.commit()
    return redirect(url_for('display', current_user=current_user))


@app.route('/logout')
def logout():
    logout_user()
    return redirect(url_for('home'))


if __name__ == '__main__':
    app.run(debug=True)

