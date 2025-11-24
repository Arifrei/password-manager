from flask import Flask, render_template, flash, request, redirect, url_for
from random import choice, randint, shuffle
from werkzeug.security import generate_password_hash, check_password_hash
from flask_sqlalchemy import SQLAlchemy
from sqlalchemy.orm import Mapped, mapped_column, relationship
from sqlalchemy import Integer, String, ForeignKey
from flask_login import UserMixin, login_user, LoginManager, login_required, current_user, logout_user
from flask_wtf.csrf import CSRFProtect, generate_csrf
from flask_limiter import Limiter
from flask_limiter.util import get_remote_address
from cryptography.fernet import Fernet, InvalidToken
from dotenv import load_dotenv
from cryptography.fernet import InvalidToken
import json
from json import JSONDecodeError
import os
import sys

if 'app' in globals():
    print("ERROR: main.py is being loaded twice! Exiting to prevent mapper conflicts.")
    sys.exit(1)

load_dotenv()

app = Flask(__name__)
app.config["SECRET_KEY"] = os.getenv("FLASK_KEY")

# CSRF Protection
csrf = CSRFProtect(app)


# Make csrf_token() available in templates and generate a token per request
@app.context_processor
def inject_csrf_token():
    return dict(csrf_token=generate_csrf)


# Rate Limiting
limiter = Limiter(
    app=app,
    key_func=get_remote_address,
    default_limits=["200 per day", "50 per hour"],
    storage_uri="memory://"
)

key = os.getenv("ENCRYPTION_KEY").encode()
cipher = Fernet(key)

database_url = os.getenv('DATABASE_URL')
if database_url and database_url.strip():
    database_url = database_url.strip()
    if database_url.startswith('"') or database_url.startswith("'"):
        database_url = database_url.strip('"').strip("'")
    if database_url.startswith('postgres://'):
        database_url = database_url.replace('postgres://', 'postgresql://', 1)
    app.config['SQLALCHEMY_DATABASE_URI'] = database_url
else:
    app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///passwords.db'

app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False

# Use Flask-SQLAlchemy's default base
db = SQLAlchemy()
db.init_app(app)

login_manager = LoginManager()
login_manager.login_view = 'login'
login_manager.init_app(app)


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
    # Store encrypted values as TEXT (Fernet tokens as strings)
    username: Mapped[str] = mapped_column(String, nullable=False)
    password: Mapped[str] = mapped_column(String, nullable=False)
    # Encrypted JSON for custom fields, stored as string token
    additional_fields: Mapped[str] = mapped_column(String, nullable=True)
    user: Mapped["Users"] = relationship(back_populates="passwords")


def _normalize_to_bytes(token) -> bytes | None:
    """Convert DB value (str/bytes/memoryview/None) to bytes or None."""
    if token is None:
        return None

    # If it's already bytes or memoryview, just normalize to bytes
    if isinstance(token, bytes):
        return token
    if isinstance(token, memoryview):
        return bytes(token)

    # If it's a hex-style string from BYTEA (e.g. "\\x6741...")
    if isinstance(token, str) and token.startswith("\\x") and len(token) > 2:
        try:
            return bytes.fromhex(token[2:])
        except ValueError:
            # Fall back to encoding as plain text
            return token.encode()

    # Anything else -> stringify and encode
    return str(token).encode()


def decrypt_or_plain(token) -> str:
    """
    Try to decrypt a Fernet token stored as TEXT/BYTEA/memoryview.
    Handles:
      - proper Fernet strings
      - raw Fernet bytes
      - Postgres BYTEA hex like "\\x6741..."
    On failure, returns a best-effort plaintext string.
    """
    token_bytes = _normalize_to_bytes(token)
    if token_bytes is None:
        return ""

    try:
        # Happy path: it's a valid Fernet token
        return cipher.decrypt(token_bytes).decode()
    except InvalidToken:
        # Not a valid token → fall back to something human-readable
        if isinstance(token, str) and token.startswith("\\x") and len(token) > 2:
            try:
                return bytes.fromhex(token[2:]).decode(errors="ignore")
            except ValueError:
                pass
        # Last resort: decode bytes or stringify
        try:
            return token_bytes.decode(errors="ignore")
        except Exception:
            return str(token)


def decrypt_json_or_empty(token) -> list:
    """
    Decrypt JSON stored as a Fernet token.
    Handles TEXT/BYTEA/memoryview and BYTEA-hex strings.
    On failure (old/plain or bad JSON), returns [].
    """
    token_bytes = _normalize_to_bytes(token)
    if token_bytes is None:
        return []

    try:
        decrypted = cipher.decrypt(token_bytes).decode()
        return json.loads(decrypted)
    except (InvalidToken, JSONDecodeError, ValueError):
        return []


@login_manager.user_loader
def load_user(user_id):
    return db.session.get(Users, user_id)


@app.route("/")
def welcome():
    # Redirect to home if user is already logged in
    if current_user.is_authenticated:
        return redirect(url_for('home'))
    return render_template('welcome.html')


@app.route("/register", methods=["GET", "POST"])
@limiter.limit("5 per hour")  # Prevent registration spam
def register():
    if request.method == "POST":
        form = request.form
        # Convert email to lowercase to prevent duplicates
        email_lowercase = form['email'].lower().strip()

        user = db.session.execute(
            db.select(Users).where(Users.email == email_lowercase)
        ).scalar()
        if user:
            flash('The email you entered is already registered. Try logging in instead')
            return redirect(url_for('login'))
        else:
            password = generate_password_hash(form['password'])
            new_user = Users(
                name=form['name'],
                email=email_lowercase,
                password=password
            )
            db.session.add(new_user)
            db.session.commit()
            login_user(new_user)
            return redirect(url_for('home'))
    return render_template('register.html')


@app.route("/login", methods=["GET", "POST"])
@limiter.limit("10 per minute")  # Prevent brute force attacks
def login():
    if request.method == "POST":
        form = request.form
        # Convert email to lowercase for consistent login
        email_lowercase = form['email'].lower().strip()

        user = db.session.execute(
            db.select(Users).where(Users.email == email_lowercase)
        ).scalar()
        if not user:
            flash('The email you entered is not registered', 'error')
        elif not check_password_hash(user.password, form['password']):
            flash('The password you entered does not match', 'error')
        else:
            login_user(user)
            return redirect(url_for('home'))
    return render_template('login.html')


# ---------------------- Passwords -------------------------

@app.route("/home")
@login_required
def home():
    info = db.session.execute(
        db.select(Passwords).where(Passwords.user_id == current_user.id)
    ).scalars().all()

    # Decrypt usernames/passwords (or show plaintext if old rows)
    username_list = [decrypt_or_plain(p.username) for p in info]
    password_list = [decrypt_or_plain(p.password) for p in info]

    # Decrypt additional fields if they exist
    additional_fields_list = [decrypt_json_or_empty(p.additional_fields) for p in info]

    data = list(zip(info, username_list, password_list, additional_fields_list))
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
            return render_template('add.html', password=password, form_data=form)
        elif action == "save":
            entries = db.session.execute(
                db.select(Passwords).where(Passwords.user_id == current_user.id)
            ).scalars().all()
            if any(entry.site == form['site'] for entry in entries):
                flash('The site/app you entered is already registered.')

            # Build additional fields list from form data
            additional_fields = []
            field_index = 0
            while f'field_label_{field_index}' in form:
                label = form.get(f'field_label_{field_index}')
                value = form.get(f'field_value_{field_index}')
                if label and value:
                    additional_fields.append({
                        'label': label,
                        'value': value
                    })
                field_index += 1

            # Encrypt additional fields JSON as string token
            additional_fields_token = None
            if additional_fields:
                additional_fields_json = json.dumps(additional_fields)
                additional_fields_token = cipher.encrypt(
                    additional_fields_json.encode()
                ).decode()

            new_entry = Passwords(
                site=form['site'],
                username=cipher.encrypt(form['username'].encode()).decode(),
                password=cipher.encrypt(form['password'].encode()).decode(),
                additional_fields=additional_fields_token,
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


@app.route("/bulk-delete", methods=["POST"])
@login_required
def bulk_delete():
    form = request.form
    entry_ids_json = form.get('entry_ids')

    if not entry_ids_json:
        flash('No entries selected for deletion.', 'error')
        return redirect(url_for('home'))

    try:
        entry_ids = json.loads(entry_ids_json)
        deleted_count = 0

        for entry_id in entry_ids:
            entry = db.session.get(Passwords, int(entry_id))
            if entry and entry.user_id == current_user.id:  # Security check
                db.session.delete(entry)
                deleted_count += 1

        db.session.commit()

        if deleted_count > 0:
            flash(f'Successfully deleted {deleted_count} password{"s" if deleted_count != 1 else ""}.', 'success')
        else:
            flash('No passwords were deleted.', 'error')

    except Exception as e:
        db.session.rollback()
        flash('An error occurred while deleting passwords.', 'error')

    return redirect(url_for('home'))


@app.route("/edit-password/<int:entry_id>", methods=["GET", "POST"])
@login_required
def edit_password(entry_id):
    # Get the password entry
    entry = db.get_or_404(Passwords, entry_id)

    # Security check: ensure user owns this password
    if entry.user_id != current_user.id:
        flash('Unauthorized access.', 'error')
        return redirect(url_for('home'))

    if request.method == "POST":
        form = request.form
        action = form.get("action")

        # Handle initial verification
        if action == "verify":
            account_password = form.get('account_password')
            if not account_password or not check_password_hash(current_user.password, account_password):
                flash('Incorrect account password. Please try again.', 'error')
                return render_template('edit.html', entry=entry, show_verification=True)

            # Verification successful - show edit form
            decrypted_username = decrypt_or_plain(entry.username)
            decrypted_password = decrypt_or_plain(entry.password)
            additional_fields = decrypt_json_or_empty(entry.additional_fields)

            return render_template(
                'edit.html',
                entry=entry,
                current_username=decrypted_username,
                current_password=decrypted_password,
                additional_fields=additional_fields,
                verified=True
            )

        # Handle password generation (only if already verified)
        elif action == "generate":
            password = pass_generator()
            decrypted_username = decrypt_or_plain(entry.username)
            decrypted_password = decrypt_or_plain(entry.password)
            additional_fields = decrypt_json_or_empty(entry.additional_fields)

            return render_template(
                'edit.html',
                entry=entry,
                current_username=decrypted_username,
                current_password=decrypted_password,
                additional_fields=additional_fields,
                generated_password=password,
                verified=True,
                form_data=form
            )

        # Handle save (only if already verified)
        elif action == "save":
            # Update the entry
            entry.site = form['site']
            entry.username = cipher.encrypt(form['username'].encode()).decode()
            entry.password = cipher.encrypt(form['password'].encode()).decode()

            # Build additional fields list from form data
            additional_fields = []
            field_index = 0
            while f'field_label_{field_index}' in form:
                label = form.get(f'field_label_{field_index}')
                value = form.get(f'field_value_{field_index}')
                if label and value:
                    additional_fields.append({
                        'label': label,
                        'value': value
                    })
                field_index += 1

            # Encrypt additional fields JSON as string token
            if additional_fields:
                additional_fields_json = json.dumps(additional_fields)
                entry.additional_fields = cipher.encrypt(
                    additional_fields_json.encode()
                ).decode()
            else:
                entry.additional_fields = None

            db.session.commit()
            flash('Password updated successfully!', 'success')
            return redirect(url_for('home'))

    # GET request - show verification form first
    return render_template('edit.html', entry=entry, show_verification=True)


# ---------------------- Other routes ----------------------

@app.route("/logout")
def logout():
    logout_user()
    return redirect(url_for('welcome'))


@app.route("/example")
def example():
    # Hardcoded example data - no real user data exposed
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

    from flask import session
    deleted_ids = session.get('deleted_examples', [])
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


# ---------------------- Password generator ----------------

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
    # Create tables if they don't exist
    with app.app_context():
        db.create_all()

    # Use environment variable for debug mode (default: False for production)
    debug_mode = os.getenv("FLASK_DEBUG", "False").lower() == "true"
    app.run(debug=debug_mode)