from flask import Blueprint, render_template, request, flash, redirect, url_for, jsonify
from flask_login import login_required, current_user
from sqlalchemy import func

from . import db
from .models import Category, Passwords

account_bp = Blueprint('account', __name__)


@account_bp.route("/categories")
@login_required
def manage_categories():
    """Page to view, rename, and delete categories."""
    categories_with_counts = db.session.query(
        Category.id,
        Category.name,
        func.count(Passwords.id).label('password_count')
    ).outerjoin(Category.passwords).filter(Category.user_id == current_user.id).group_by(Category.id).order_by(Category.name).all()
    
    return render_template('manage_categories.html', categories=categories_with_counts)


@account_bp.route("/categories/rename/<int:category_id>", methods=["POST"])
@login_required
def rename_category(category_id):
    category = db.get_or_404(Category, category_id)
    if category.user_id != current_user.id:
        return "Unauthorized", 403
    
    new_name = request.form.get('new_name', '').strip()
    if new_name:
        category.name = new_name
        db.session.commit()
        flash(f'Category renamed to "{new_name}".', 'success')
    else:
        flash('New category name cannot be empty.', 'error')
        
    return redirect(url_for('account.manage_categories'))


@account_bp.route("/categories/delete/<int:category_id>", methods=["POST"])
@login_required
def delete_category(category_id):
    category = db.get_or_404(Category, category_id)
    if category.user_id != current_user.id:
        return "Unauthorized", 403
    
    db.session.delete(category)
    db.session.commit()
    flash(f'Category "{category.name}" has been deleted.', 'success')
    return redirect(url_for('account.manage_categories'))