import os
from flask import Flask, session, redirect, url_for, flash, request
from flask_sqlalchemy import SQLAlchemy
from flask_login import LoginManager, current_user, logout_user
from flask_wtf.csrf import CSRFProtect, generate_csrf
from flask_limiter import Limiter
from flask_limiter.util import get_remote_address
from dotenv import load_dotenv
from flask_migrate import Migrate
from datetime import datetime, timedelta
import threading

# Initialize extensions
db = SQLAlchemy()
csrf = CSRFProtect()
limiter = Limiter(key_func=get_remote_address, storage_uri="memory://")
login_manager = LoginManager()
migrate = Migrate()


def create_app():
    """Create and configure an instance of the Flask application."""
    load_dotenv()

    app = Flask(__name__)

    # --- Configuration ---
    app.config["SECRET_KEY"] = os.getenv("FLASK_KEY")
    database_url = os.getenv('DATABASE_URL', 'sqlite:///passwords.db').strip().strip('"\'')
    if database_url.startswith('postgres://'):
        database_url = database_url.replace('postgres://', 'postgresql://', 1)
    app.config['SQLALCHEMY_DATABASE_URI'] = database_url
    app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
    app.config['PERMANENT_SESSION_LIFETIME'] = timedelta(minutes=15)
    app.config['SESSION_COOKIE_SECURE'] = os.getenv("FLASK_ENV") == "production"
    app.config['SESSION_COOKIE_HTTPONLY'] = True
    app.config['SESSION_COOKIE_SAMESITE'] = 'Lax'

    # --- Initialize Extensions ---
    db.init_app(app)
    csrf.init_app(app)
    limiter.init_app(app)
    login_manager.init_app(app)
    migrate.init_app(app, db)
    login_manager.login_view = 'auth.login'

    # --- Import Blueprints and Models ---
    from . import models
    from .auth import auth_bp
    from .passwords import passwords_bp
    from .account import account_bp
    from .categories import categories_bp
    from .utils import favicon_worker

    # --- Register Blueprints ---
    app.register_blueprint(auth_bp)
    app.register_blueprint(passwords_bp)
    app.register_blueprint(account_bp)
    app.register_blueprint(categories_bp)

    # --- App Context Processors and Hooks ---
    @app.context_processor
    def inject_csrf_token():
        return dict(csrf_token=generate_csrf)

    @login_manager.user_loader
    def load_user(user_id):
        return db.session.get(models.Users, user_id)

    @app.before_request
    def check_session_timeout():
        if request.endpoint and (request.endpoint.startswith('static') or request.endpoint in ['auth.login', 'auth.register', 'passwords.welcome', 'passwords.example']):
            return

        if current_user.is_authenticated:
            last_activity = session.get('last_activity')
            if last_activity:
                now = datetime.now()
                last_time = datetime.fromisoformat(last_activity)
                inactive_duration = now - last_time
                remember_me = session.get('remember_me', False)
                timeout = timedelta(days=30) if remember_me else timedelta(minutes=15)

                if inactive_duration > timeout:
                    logout_user()
                    session.clear()
                    flash('Your session has expired due to inactivity. Please login again.', 'info')
                    return redirect(url_for('auth.login'))

            session['last_activity'] = datetime.now().isoformat()
            session.modified = True

    @app.after_request
    def add_cache_headers(response):
        if current_user.is_authenticated and request.endpoint and not request.endpoint.startswith('static'):
            response.headers['Cache-Control'] = 'no-store, no-cache, must-revalidate, post-check=0, pre-check=0, max-age=0'
            response.headers['Pragma'] = 'no-cache'
            response.headers['Expires'] = '-1'
        return response

    # --- Create Database and Start Worker ---
    with app.app_context():
        db.create_all()

    return app