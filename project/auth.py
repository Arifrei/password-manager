import base64
import os
from datetime import datetime, timedelta

from flask import Blueprint, render_template, request, flash, redirect, url_for, session, jsonify
from werkzeug.security import generate_password_hash, check_password_hash
from flask_login import login_user, logout_user, login_required, current_user

from . import db, limiter
from .models import Users

auth_bp = Blueprint('auth', __name__)


@auth_bp.route("/register", methods=["GET", "POST"])
@limiter.limit("5 per hour")
def register():
    if request.method == "POST":
        form = request.form
        email_lowercase = form['email'].lower().strip()

        user = db.session.execute(
            db.select(Users).where(Users.email == email_lowercase)
        ).scalar()

        if user:
            flash('The email you entered is already registered. Try logging in instead.', 'error')
            return redirect(url_for('auth.login'))

        password = generate_password_hash(form['password'])
        salt = form.get('encryption_salt') or base64.urlsafe_b64encode(os.urandom(16)).decode()
        new_user = Users(
            name=form['name'],
            email=email_lowercase,
            password=password,
            encryption_salt=salt
        )
        db.session.add(new_user)
        db.session.commit()
        login_user(new_user)
        return redirect(url_for('passwords.home'))

    registration_salt = base64.urlsafe_b64encode(os.urandom(16)).decode()
    return render_template('register.html', registration_salt=registration_salt)


@auth_bp.route("/login", methods=["GET", "POST"])
@limiter.limit("10 per minute")
def login():
    if request.method == "POST":
        form = request.form
        email_lowercase = form['email'].lower().strip()

        user = db.session.execute(
            db.select(Users).where(Users.email == email_lowercase)
        ).scalar()

        if not user:
            flash('The email you entered is not registered.', 'error')
        elif not check_password_hash(user.password, form['password']):
            flash('The password you entered does not match.', 'error')
        else:
            remember = 'remember' in form
            login_user(user, remember=remember)

            session.permanent = True
            session['remember_me'] = remember
            session['last_activity'] = datetime.now().isoformat()

            return redirect(url_for('passwords.home'))

    return render_template('login.html')


@auth_bp.route("/auth/salt")
@limiter.limit("30 per hour")
def fetch_user_salt():
    """Return the per-user salt so the browser can derive the vault key client-side."""
    email = request.args.get('email', '').lower().strip()
    if not email:
        return jsonify({"salt": None}), 400

    user = db.session.execute(
        db.select(Users).where(Users.email == email)
    ).scalar()

    return jsonify({"salt": user.encryption_salt if user else None})


@auth_bp.route("/api/encryption-salt")
@login_required
def current_user_salt():
    """Expose the salt for the logged-in user for client-side key derivation."""
    return jsonify({"salt": current_user.encryption_salt})


@auth_bp.route("/logout")
def logout():
    logout_user()
    session.clear()
    return redirect(url_for('passwords.welcome'))
