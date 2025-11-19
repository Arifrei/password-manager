from flask import Flask, render_template, flash, request, redirect, url_for
from random import choice, randint, shuffle
from werkzeug.security import generate_password_hash, check_password_hash
from flask_sqlalchemy import SQLAlchemy
from sqlalchemy.orm import DeclarativeBase, Mapped, mapped_column, relationship
from sqlalchemy import Integer, String, ForeignKey, LargeBinary
from flask_login import UserMixin, login_user, LoginManager, login_required, current_user, logout_user
from cryptography.fernet import Fernet
from dotenv import load_dotenv
import json
import os

load_dotenv()

app = Flask(__name__)
app.config["SECRET_KEY"] = os.getenv("FLASK_KEY")

key = os.getenv("ENCRYPTION_KEY").encode()
cipher = Fernet(key)


class Base(DeclarativeBase):
    pass

database_url = os.getenv('DATABASE_URL')
if database_url:
    if database_url.startswith('postgres://'):
        database_url = database_url.replace('postgres://', 'postgresql://', 1)
    app.config['SQLALCHEMY_DATABASE_URI'] = database_url
else:
    app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///passwords.db'

app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False

db = SQLAlchemy(model_class=Base)
db.init_app(app)

login_manager = LoginManager()
login_manager.login_view = 'login'
login_manager.init_app(app)


@login_manager.user_loader
def load_user(user_id):
    return db.session.get(Users, user_id)


class Users(db.Model, UserMixin):
    __tablename__ = "users"
    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    email: Mapped[str] = mapped_column(String(100), unique=True)
    password: Mapped[str] = mapped_column(String(100))
    name: Mapped[str] = mapped_column(String(1000))
    passwords: Mapped[list["Passwords"]] = relationship(back_populates="user")

    def __init__(self, name, email, password):
        self.name = name
        self.email = email
        self.password = password


class Passwords(db.Model):
    __tablename__ = "passwords"
    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    user_id: Mapped[int] = mapped_column(ForeignKey("users.id"))
    site: Mapped[str] = mapped_column(String, nullable=False)
    username: Mapped[str] = mapped_column(String, nullable=False)
    password: Mapped[str] = mapped_column(LargeBinary, nullable=False)
    user: Mapped["Users"] = relationship(back_populates="passwords")


with app.app_context():
    db.create_all()


@app.route("/")
def welcome():
    return render_template('welcome.html')


@app.route("/register", methods=["GET", "POST"])
def register():
    if request.form:
        form = request.form
        user = db.session.execute(db.select(Users).where(Users.email == form['email'])).scalar()
        if user:
            flash('The email you entered is already registered. Try logging in instead')
            return redirect(url_for('login'))
        else:
            password = generate_password_hash(form['password'], 'pbkdf2:sha256', 6)
            new_user = Users(
                name=form['name'],
                email=form['email'],
                password=password
            )
            db.session.add(new_user)
            db.session.commit()
            login_user(new_user)
            return redirect(url_for('home'))
    return render_template('register.html')


@app.route("/login", methods=["GET", "POST"])
def login():
    if request.form:
        form = request.form
        user = db.session.execute(db.select(Users).where(Users.email == form['email'])).scalar()
        if not user:
            flash('The email you entered is not registered', 'error')
        elif not check_password_hash(user.password, form['password']):
            flash('The password you entered does not match', 'error')
        else:
            login_user(user)
            return redirect(url_for('home'))
    return render_template('login.html')


@app.route("/home")
@login_required
def home():
    info = db.session.execute(db.select(Passwords).where(Passwords.user_id == current_user.id)).scalars().all()
    password_list = [cipher.decrypt(p.password).decode() for p in info]
    data = list(zip(info, password_list))
    return render_template('index.html', data=data)


@app.route("/add-password", methods=["GET", "POST"])
@login_required
def add_password():
    if request.method == "POST":
        form = request.form
        action = form.get("action")
        if action == "generate":
            password = pass_generator()
            print(password)
            return render_template('add.html', password=password)
        elif action == "save":
            entries = db.session.execute(
                db.select(Passwords).where(Passwords.user_id == current_user.id)).scalars().all()
            if any(entry.site == form['site'] for entry in entries):
                flash('The site/app you entered is already registered.')
            new_entry = Passwords(
                site=form['site'],
                username=form['username'],
                password=cipher.encrypt(form['password'].encode()),
                user_id=current_user.id
            )
            db.session.add(new_entry)
            db.session.commit()
            return redirect(url_for('home'))
    return render_template('add.html')


@app.route("/delete/<int:entry_id>")
@login_required
def delete_entry(entry_id):
    entry_to_delete = db.get_or_404(Passwords, entry_id)
    db.session.delete(entry_to_delete)
    db.session.commit()
    return redirect(url_for('home'))


@app.route("/logout")
def logout():
    logout_user()
    return redirect(url_for('welcome'))


@app.route("/example")
def example():
    class ExampleEntry:
        def __init__(self, entry_id, site, username, password_text):
            self.site = site
            self.username = username
            self.id = entry_id

    all_examples = [
        (ExampleEntry(1, "Gmail", "john.doe@gmail.com", "ExamplePass123!"), "ExamplePass123!"),
        (ExampleEntry(2, "Facebook", "johndoe@example.com", "SecureP@ssw0rd"), "SecureP@ssw0rd"),
        (ExampleEntry(3, "Twitter", "@johndoe", "MyTw1tt3r!Pass"), "MyTw1tt3r!Pass"),
        (ExampleEntry(4, "LinkedIn", "john.doe@example.com", "Pr0f3ssional#2024"), "Pr0f3ssional#2024"),
    ]

    # Get deleted IDs from session
    from flask import session
    deleted_ids = session.get('deleted_examples', [])

    # Filter out deleted entries
    example_data = [entry for entry in all_examples if entry[0].id not in deleted_ids]

    return render_template('example.html', data=example_data)


@app.route("/delete-example/<int:entry_id>")
def delete_example(entry_id):
    from flask import session
    deleted_ids = session.get('deleted_examples', [])

    if entry_id not in deleted_ids:
        deleted_ids.append(entry_id)

    session['deleted_examples'] = deleted_ids

    return redirect(url_for('example'))


letters = list("abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ")
numbers = list("0123456789")
symbols = list("!#$%&()*+")


def pass_generator():
    password_list = []
    password_list += [choice(letters) for _ in range(randint(8, 10))]
    password_list += [choice(numbers) for _ in range(randint(2, 4))]
    password_list += [choice(symbols) for _ in range(randint(2, 4))]
    shuffle(password_list)
    return "".join(password_list)


if __name__ == "__main__":
    app.run(debug=True)