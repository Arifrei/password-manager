from flask import Blueprint, render_template, request, flash, redirect, url_for, session
from werkzeug.security import generate_password_hash, check_password_hash
from flask_login import login_user, logout_user
from datetime import datetime, timedelta

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
        new_user = Users(
            name=form['name'],
            email=email_lowercase,
            password=password
        )
        db.session.add(new_user)
        db.session.commit()
        login_user(new_user)
        return redirect(url_for('passwords.home'))

    return render_template('register.html')


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


@auth_bp.route("/logout")
def logout():
    logout_user()
    session.clear()
    return redirect(url_for('passwords.welcome'))