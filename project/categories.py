from flask import Blueprint, render_template, request, flash, redirect, url_for
from flask_login import login_required, current_user
from .models import Category, Users
from . import db
from sqlalchemy.exc import IntegrityError

categories_bp = Blueprint('categories', __name__)


@categories_bp.route('/categories')
@login_required
def list_categories():
    # The relationship on the Users model is named 'categories'
    user_categories = current_user.categories
    user_categories.sort(key=lambda c: c.name)
    return render_template('categories.html', categories=user_categories)


@categories_bp.route('/categories/add', methods=['GET', 'POST'])
@login_required
def add_category():
    if request.method == 'POST':
        name = request.form.get('name')
        if not name:
            flash('Category name is required.', category='error')
        else:
            # Check for existing category for this user
            existing_category = Category.query.filter_by(user_id=current_user.id, name=name).first()
            if existing_category:
                flash('Category with this name already exists.', category='error')
            else:
                new_category = Category(name=name, user_id=current_user.id)
                db.session.add(new_category)
                db.session.commit()
                flash('Category added successfully!', category='success')
                return redirect(url_for('categories.list_categories'))
    return render_template('category_form.html', action='Add')


@categories_bp.route('/categories/edit/<int:category_id>', methods=['GET', 'POST'])
@login_required
def edit_category(category_id):
    category = db.get_or_404(Category, category_id)
    if category.user_id != current_user.id:
        flash('You do not have permission to edit this category.', category='error')
        return redirect(url_for('categories.list_categories'))

    if request.method == 'POST':
        name = request.form.get('name')
        if not name:
            flash('Category name is required.', category='error')
        else:
            category.name = name
            db.session.commit()
            flash('Category updated successfully!', category='success')
            return redirect(url_for('categories.list_categories'))

    return render_template('category_form.html', category=category, action='Edit')


@categories_bp.route('/categories/delete/<int:category_id>', methods=['POST'])
@login_required
def delete_category(category_id):
    category = db.get_or_404(Category, category_id)
    if category.user_id == current_user.id:
        db.session.delete(category)
        db.session.commit()
        flash('Category deleted.', category='success')
    else:
        flash('You do not have permission to delete this category.', category='error')
    return redirect(url_for('categories.list_categories'))