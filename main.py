from flask import Flask, render_template, flash, request, redirect, url_for, session
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
from datetime import datetime, timedelta
import json
from json import JSONDecodeError
import os
import sys
import requests
from urllib.parse import urlparse, urljoin
from io import BytesIO
from PIL import Image
from queue import Queue
import threading
import hashlib

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

# Favicon storage configuration
FAVICON_FOLDER = os.path.join(os.path.dirname(__file__), 'static', 'favicons')
os.makedirs(FAVICON_FOLDER, exist_ok=True)
os.makedirs(os.path.join(os.path.dirname(__file__), 'static'), exist_ok=True)

# Session timeout configuration (15 minutes of inactivity)
app.config['PERMANENT_SESSION_LIFETIME'] = timedelta(minutes=15)
app.config['SESSION_COOKIE_SECURE'] = False  # Set to True in production with HTTPS
app.config['SESSION_COOKIE_HTTPONLY'] = True
app.config['SESSION_COOKIE_SAMESITE'] = 'Lax'

# Use Flask-SQLAlchemy's default base
db = SQLAlchemy()
db.init_app(app)

login_manager = LoginManager()
login_manager.login_view = 'login'
login_manager.init_app(app)


# --- Background Favicon Fetching Setup ---
favicon_queue = Queue()


def favicon_worker():
    """
    Worker thread that processes favicon fetching jobs from a queue.
    """
    # Create a separate app context for the background thread
    with app.app_context():
        while True:
            entry_id, site_name = favicon_queue.get()
            if entry_id is None:  # Sentinel value to stop the worker
                break

            try:
                filename = fetch_and_save_favicon(site_name)
                if filename:
                    entry = db.session.get(Passwords, entry_id)
                    if entry:
                        entry.favicon = filename
                        db.session.commit()
            except Exception as e:
                print(f"Error in favicon worker for site '{site_name}': {e}")
                db.session.rollback()
            finally:
                favicon_queue.task_done()


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
    # Favicon filename (e.g., "google_com.png")
    favicon: Mapped[str] = mapped_column(String, nullable=True)
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


# ---------------------- Favicon Fetching Functions ----------------------

def extract_domain_from_site(site_name):
    """
    Extract a clean domain from various site name formats.
    Examples:
      - "Gmail" -> "gmail.com"
      - "google.com" -> "google.com"
      - "https://github.com" -> "github.com"
      - "Facebook Login" -> "facebook.com"
    """
    site_name = site_name.lower().strip()

    # Remove common suffixes
    site_name = site_name.replace(' login', '').replace(' account', '').replace(' app', '').strip()

    # If it looks like a URL, parse it
    if '://' in site_name or site_name.startswith('www.'):
        parsed = urlparse(site_name if '://' in site_name else f'http://{site_name}')
        domain = parsed.netloc or parsed.path
        domain = domain.replace('www.', '')
        return domain

    # If it already looks like a domain
    if '.' in site_name and ' ' not in site_name:
        return site_name.replace('www.', '')

    # Otherwise, assume it's a brand name and add .com
    site_name = site_name.split()[0]  # Take first word
    return f"{site_name}.com"


def get_favicon_filename(site_name):
    """Generate a consistent filename for a favicon based on site name"""
    domain = extract_domain_from_site(site_name)
    # Create a safe filename
    safe_name = domain.replace('.', '_').replace('/', '_').replace(':', '_')
    return f"{safe_name}.png"


def fetch_and_save_favicon(site_name):
    domain = extract_domain_from_site(site_name)
    filename = get_favicon_filename(site_name)
    filepath = os.path.join(FAVICON_FOLDER, filename)

    # If favicon already exists, return it
    if os.path.exists(filepath):
        return filename

    # List of favicon URLs to try
    favicon_urls = [
        f"https://www.google.com/s2/favicons?domain={domain}&sz=128",
        f"https://icons.duckduckgo.com/ip3/{domain}.ico",
        f"https://{domain}/favicon.ico",
        f"https://www.{domain}/favicon.ico",
    ]

    for url in favicon_urls:
        try:
            response = requests.get(url, timeout=5, headers={
                'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36'
            })

            if response.status_code == 200 and len(response.content) > 0:
                # Try to open as image to validate
                try:
                    img = Image.open(BytesIO(response.content))

                    # Skip very small images (likely placeholders)
                    if img.size[0] < 10 or img.size[1] < 10:
                        continue

                    # Convert to PNG and resize to 32x32
                    img = img.convert('RGBA')
                    img = img.resize((32, 32), Image.Resampling.LANCZOS)

                    # Save as PNG
                    img.save(filepath, 'PNG')
                    return filename

                except Exception as e:
                    # Not a valid image, try next URL
                    continue

        except Exception as e:
            # Network error or timeout, try next URL
            continue

    # If all attempts failed, return None (will use default icon)
    return None


@login_manager.user_loader
def load_user(user_id):
    return db.session.get(Users, user_id)


@app.before_request
def check_session_timeout():
    """Check session timeout and force logout if expired"""
    # Skip for static files and public routes
    if request.endpoint and (request.endpoint == 'static' or
                             request.endpoint in ['welcome', 'login', 'register', 'example']):
        return

    if current_user.is_authenticated:
        # Check if session has 'last_activity' timestamp
        last_activity = session.get('last_activity')

        if last_activity:
            # Calculate time since last activity
            now = datetime.now()
            last_time = datetime.fromisoformat(last_activity)
            inactive_duration = now - last_time

            # Get timeout based on remember me status
            remember_me = session.get('remember_me', False)
            timeout = timedelta(days=30) if remember_me else timedelta(minutes=15)

            # If inactive too long, logout
            if inactive_duration > timeout:
                logout_user()
                session.clear()
                flash('Your session has expired due to inactivity. Please login again.', 'error')
                return redirect(url_for('login'))

        # Update last activity timestamp
        session['last_activity'] = datetime.now().isoformat()
        session.modified = True


@app.after_request
def add_cache_headers(response):
    """Prevent caching of sensitive pages"""
    # Don't cache authenticated pages
    if current_user.is_authenticated and request.endpoint not in ['static']:
        response.headers['Cache-Control'] = 'no-store, no-cache, must-revalidate, post-check=0, pre-check=0, max-age=0'
        response.headers['Pragma'] = 'no-cache'
        response.headers['Expires'] = '-1'
    return response


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
            # Check if "Remember Me" was checked
            remember = form.get('remember', False)

            # Login user with remember option
            login_user(user, remember=remember)

            # Set session as permanent if remember me is checked
            if remember:
                session.permanent = True
                app.permanent_session_lifetime = timedelta(days=30)
                session['remember_me'] = True
            else:
                session.permanent = True  # Still use permanent session for timeout
                app.permanent_session_lifetime = timedelta(minutes=15)
                session['remember_me'] = False

            # Set initial last activity timestamp
            session['last_activity'] = datetime.now().isoformat()

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

    # Build favicon URLs directly from the database. This is fast.
    favicon_list = []
    for p in info:
        url = url_for('static', filename=f'favicons/{p.favicon}') if p.favicon else None
        favicon_list.append(url)

    data = list(zip(info, username_list, password_list, additional_fields_list, favicon_list))
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
                favicon=None,  # Will be fetched in the background
                user_id=current_user.id
            )
            db.session.add(new_entry)
            db.session.commit()
            # Add a job to the background queue to fetch the favicon
            favicon_queue.put((new_entry.id, new_entry.site))
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

            original_site = entry.site
            entry.site = form['site'] # Update site name now

            # Update favicon if site name changed
            if original_site != entry.site:
                entry.favicon = None  # Reset favicon, will be fetched in background
                favicon_queue.put((entry.id, entry.site))

            db.session.commit()
            flash('Password updated successfully!', 'success')
            return redirect(url_for('home'))

    # GET request - show verification form first
    return render_template('edit.html', entry=entry, show_verification=True)


# ---------------------- Export routes ----------------------

@app.route("/export/csv")
@login_required
def export_csv():
    """Export all passwords to CSV format"""
    import csv
    from io import StringIO

    # Get all user's passwords
    entries = db.session.execute(
        db.select(Passwords).where(Passwords.user_id == current_user.id)
    ).scalars().all()

    # Create CSV in memory
    output = StringIO()
    writer = csv.writer(output)

    # Write header
    writer.writerow(['Site', 'Username', 'Password', 'Additional Fields'])

    # Write data
    for entry in entries:
        username = decrypt_or_plain(entry.username)
        password = decrypt_or_plain(entry.password)

        # Decrypt additional fields
        additional_fields_str = ''
        if entry.additional_fields:
            try:
                decrypted = decrypt_or_plain(entry.additional_fields)
                fields = json.loads(decrypted)
                # Format as "Label: Value; Label2: Value2"
                additional_fields_str = '; '.join([f"{f['label']}: {f['value']}" for f in fields])
            except:
                pass

        writer.writerow([entry.site, username, password, additional_fields_str])

    # Prepare response
    output.seek(0)
    from flask import make_response
    response = make_response(output.getvalue())
    response.headers['Content-Disposition'] = 'attachment; filename=passwords_export.csv'
    response.headers['Content-Type'] = 'text/csv'

    return response


@app.route("/export/json")
@login_required
def export_json():
    """Export all passwords to JSON format"""
    from flask import jsonify

    # Get all user's passwords
    entries = db.session.execute(
        db.select(Passwords).where(Passwords.user_id == current_user.id)
    ).scalars().all()

    # Build JSON structure
    export_data = {
        'exported_at': datetime.now().isoformat(),
        'total_passwords': len(entries),
        'passwords': []
    }

    for entry in entries:
        username = decrypt_or_plain(entry.username)
        password = decrypt_or_plain(entry.password)

        # Decrypt additional fields
        additional_fields = []
        if entry.additional_fields:
            try:
                decrypted = decrypt_or_plain(entry.additional_fields)
                additional_fields = json.loads(decrypted)
            except:
                pass

        export_data['passwords'].append({
            'site': entry.site,
            'username': username,
            'password': password,
            'additional_fields': additional_fields
        })

    # Create response
    from flask import make_response
    response = make_response(json.dumps(export_data, indent=2))
    response.headers['Content-Disposition'] = 'attachment; filename=passwords_export.json'
    response.headers['Content-Type'] = 'application/json'

    return response


@app.route("/import", methods=["GET", "POST"])
@login_required
def import_passwords():
    """Import passwords from CSV file"""
    if request.method == "POST":
        # Check if file was uploaded
        if 'file' not in request.files:
            flash('No file uploaded.', 'error')
            return redirect(url_for('import_passwords'))

        file = request.files['file']

        # Check if file has a filename
        if file.filename == '':
            flash('No file selected.', 'error')
            return redirect(url_for('import_passwords'))

        # Check if file is CSV
        if not file.filename.endswith('.csv'):
            flash('Please upload a CSV file.', 'error')
            return redirect(url_for('import_passwords'))

        try:
            import csv
            from io import StringIO

            # Read CSV file
            csv_data = file.read().decode('utf-8')
            csv_file = StringIO(csv_data)
            reader = csv.DictReader(csv_file)

            imported_count = 0
            skipped_count = 0
            error_count = 0

            for row in reader:
                try:
                    # Get required fields
                    site = row.get('Site', '').strip()
                    username = row.get('Username', '').strip()
                    password = row.get('Password', '').strip()

                    # Skip if missing required fields
                    if not site or not username or not password:
                        skipped_count += 1
                        continue

                    # Check for duplicates (same site + username)
                    existing = db.session.execute(
                        db.select(Passwords).where(
                            Passwords.user_id == current_user.id,
                            Passwords.site == site
                        )
                    ).scalar()

                    if existing:
                        # Try to decrypt and check username
                        try:
                            existing_username = decrypt_or_plain(existing.username)
                            if existing_username == username:
                                skipped_count += 1
                                continue
                        except:
                            pass

                    # Parse additional fields if present
                    additional_fields_str = row.get('Additional Fields', '').strip()
                    additional_fields_encrypted = None

                    if additional_fields_str:
                        # Parse "Label: Value; Label2: Value2" format
                        additional_fields = []
                        pairs = additional_fields_str.split(';')
                        for pair in pairs:
                            if ':' in pair:
                                label, value = pair.split(':', 1)
                                additional_fields.append({
                                    'label': label.strip(),
                                    'value': value.strip()
                                })

                        if additional_fields:
                            additional_fields_json = json.dumps(additional_fields)
                            additional_fields_encrypted = cipher.encrypt(additional_fields_json.encode())

                    # Create new password entry
                    new_entry = Passwords(
                        site=site,
                        username=cipher.encrypt(username.encode()),
                        password=cipher.encrypt(password.encode()),
                        additional_fields=additional_fields_encrypted,
                        favicon=None,  # Will be fetched in background
                        user_id=current_user.id
                    )

                    db.session.add(new_entry)
                    # Flush to get the ID for the new entry before committing
                    db.session.flush()
                    favicon_queue.put((new_entry.id, new_entry.site))
                    imported_count += 1

                except Exception as e:
                    error_count += 1
                    continue

            # Commit all imports
            db.session.commit()

            # Show results
            message = f'Successfully imported {imported_count} password(s).'
            if skipped_count > 0:
                message += f' Skipped {skipped_count} duplicate(s).'
            if error_count > 0:
                message += f' {error_count} error(s).'

            flash(message, 'success')
            return redirect(url_for('home'))

        except Exception as e:
            db.session.rollback()
            flash(f'Error importing file: {str(e)}', 'error')
            return redirect(url_for('import_passwords'))

    # GET request - show import form
    return render_template('import.html')


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

    # Start the background favicon worker thread
    worker_thread = threading.Thread(target=favicon_worker, daemon=True)
    worker_thread.start()
    print("Background favicon worker started.")

    # Use environment variable for debug mode (default: False for production)
    debug_mode = os.getenv("FLASK_DEBUG", "False").lower() == "true"
    app.run(debug=debug_mode)