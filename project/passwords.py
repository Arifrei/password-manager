import os
import csv
import json
from datetime import datetime
from io import StringIO

from flask import (
    Blueprint, render_template, request, flash, redirect, url_for, make_response, session, jsonify
)
from flask_login import login_required, current_user
from werkzeug.security import check_password_hash
from sqlalchemy import desc

from . import db, csrf
from .models import Passwords, Category
from .utils import pass_generator, fetch_and_save_favicon, get_favicon_filename, FAVICON_FOLDER

passwords_bp = Blueprint('passwords', __name__)


@passwords_bp.route("/")
def welcome():
    if current_user.is_authenticated:
        return redirect(url_for('passwords.home'))
    return render_template('welcome.html')


@passwords_bp.route("/home")
@login_required
def home():
    category_filter = request.args.get('category')
    sort_by = request.args.get('sort', 'site')  # Default to sorting by site

    # Fetch all categories for the filter dropdown (category names are not secret metadata)
    all_user_categories = db.session.execute(
        db.select(Category.name).where(Category.user_id == current_user.id).distinct().order_by(Category.name)
    ).scalars().all()

    return render_template(
        'index.html',
        data=[],  # data is now provided client-side after decryption
        categories=all_user_categories,
        current_filter=category_filter,
        current_sort=sort_by
    )


@passwords_bp.route("/api/vault")
@login_required
def get_vault():
    """Return encrypted vault entries for the current user."""
    entries = db.session.execute(
        db.select(Passwords).where(Passwords.user_id == current_user.id).order_by(desc(Passwords.date_added))
    ).scalars().all()

    payload = [
        {
            "id": entry.id,
            "encrypted_payload": entry.encrypted_payload,
            "categories": [c.name for c in entry.categories],
            "date_added": entry.date_added.isoformat()
        } for entry in entries if entry.encrypted_payload
    ]
    return jsonify(payload)


@passwords_bp.route("/api/vault/<int:entry_id>")
@login_required
def get_vault_entry(entry_id):
    entry = db.get_or_404(Passwords, entry_id)
    if entry.user_id != current_user.id:
        return jsonify({"error": "Unauthorized"}), 403
    if not entry.encrypted_payload:
        return jsonify({"error": "Entry is missing encrypted payload"}), 400
    return jsonify({
        "id": entry.id,
        "encrypted_payload": entry.encrypted_payload,
        "categories": [c.name for c in entry.categories],
        "date_added": entry.date_added.isoformat()
    })


@passwords_bp.route("/api/vault", methods=["POST"])
@login_required
@csrf.exempt
def create_vault_entry():
    data = request.get_json(silent=True) or {}
    encrypted_payload = data.get("encrypted_payload")
    if not encrypted_payload:
        return jsonify({"error": "Missing encrypted_payload"}), 400

    category_names = data.get("categories", [])
    password_categories = []
    for cat_name in category_names:
        category = db.session.execute(db.select(Category).where(
            Category.user_id == current_user.id,
            Category.name == cat_name
        )).scalar_one_or_none()
        if not category:
            category = Category(name=cat_name, user_id=current_user.id)
            db.session.add(category)
        password_categories.append(category)

    new_entry = Passwords(
        site=None,
        username=None,
        password=None,
        additional_fields=None,
        favicon=None,
        encrypted_payload=encrypted_payload,
        user_id=current_user.id
    )
    new_entry.categories = password_categories
    db.session.add(new_entry)
    db.session.commit()

    # optional favicon fetch in background if site name present in payload
    site_hint = data.get("site", "")
    if site_hint:
        fetch_and_save_favicon(site_hint)
        new_entry.favicon = get_favicon_filename(site_hint)
        db.session.commit()

    return jsonify({
        "id": new_entry.id,
        "categories": [c.name for c in new_entry.categories],
        "date_added": new_entry.date_added.isoformat(),
        "encrypted_payload": encrypted_payload
    }), 201


@passwords_bp.route("/api/vault/<int:entry_id>", methods=["PUT"])
@login_required
@csrf.exempt
def update_vault_entry(entry_id):
    entry = db.get_or_404(Passwords, entry_id)
    if entry.user_id != current_user.id:
        return jsonify({"error": "Unauthorized"}), 403

    data = request.get_json(silent=True) or {}
    encrypted_payload = data.get("encrypted_payload")
    if not encrypted_payload:
        return jsonify({"error": "Missing encrypted_payload"}), 400

    entry.encrypted_payload = encrypted_payload
    entry.site = None
    entry.username = None
    entry.password = None
    entry.additional_fields = None
    entry.date_added = datetime.utcnow()

    entry.categories.clear()
    category_names = data.get("categories", [])
    for cat_name in category_names:
        category = db.session.execute(db.select(Category).where(
            Category.user_id == current_user.id,
            Category.name == cat_name
        )).scalar_one_or_none()
        if not category:
            category = Category(name=cat_name, user_id=current_user.id)
            db.session.add(category)
        entry.categories.append(category)

    site_hint = data.get("site", "")
    if site_hint:
        fetch_and_save_favicon(site_hint)
        entry.favicon = get_favicon_filename(site_hint)

    db.session.commit()
    return jsonify({
        "id": entry.id,
        "categories": [c.name for c in entry.categories],
        "date_added": entry.date_added.isoformat(),
        "encrypted_payload": entry.encrypted_payload
    })


@passwords_bp.route("/api/vault/<int:entry_id>", methods=["DELETE"])
@login_required
@csrf.exempt
def delete_vault_entry(entry_id):
    entry = db.get_or_404(Passwords, entry_id)
    if entry.user_id != current_user.id:
        return jsonify({"error": "Unauthorized"}), 403
    db.session.delete(entry)
    db.session.commit()
    return jsonify({"deleted": True, "id": entry_id})


@passwords_bp.route("/api/vault/bulk-delete", methods=["POST"])
@login_required
@csrf.exempt
def bulk_delete_vault():
    data = request.get_json(silent=True) or {}
    ids = data.get("ids", [])
    if not isinstance(ids, list) or not ids:
        return jsonify({"deleted": 0})
    deleted_count = db.session.query(Passwords).filter(
        Passwords.id.in_(ids),
        Passwords.user_id == current_user.id
    ).delete(synchronize_session=False)
    db.session.commit()
    return jsonify({"deleted": deleted_count})


@passwords_bp.route("/api/favicon")
@login_required
def favicon_api():
    """Return a cached favicon URL for a site, fetching and storing it if missing."""
    site = request.args.get("site", "").strip()
    if not site:
        return jsonify({"url": None})

    filename = get_favicon_filename(site)
    filepath = os.path.join(FAVICON_FOLDER, filename)
    if not os.path.exists(filepath):
        fetch_and_save_favicon(site)

    if os.path.exists(filepath):
        return jsonify({"url": url_for('static', filename=f'favicons/{filename}')})
    return jsonify({"url": None})


@passwords_bp.route("/add-password", methods=["GET", "POST"])
@login_required
def add_password():
    if request.method == "POST":
        form = request.form
        encrypted_payload = form.get("encrypted_payload")
        if not encrypted_payload:
            flash('Missing encrypted payload. Please try again.', 'error')
            return render_template('add.html', form_data=form)

        # Handle categories (category names remain plaintext metadata)
        category_names = [name.strip() for name in form.get('categories', '').split(',') if name.strip()]
        password_categories = []
        if category_names:
            for cat_name in category_names:
                category = db.session.execute(db.select(Category).where(
                    Category.user_id == current_user.id,
                    Category.name == cat_name
                )).scalar_one_or_none()
                if not category:
                    category = Category(name=cat_name, user_id=current_user.id)
                    db.session.add(category)
                password_categories.append(category)

        new_entry = Passwords(
            site=None,
            username=None,
            password=None,
            additional_fields=None,
            favicon=None,
            encrypted_payload=encrypted_payload,
            user_id=current_user.id
        )
        new_entry.categories = password_categories
        db.session.add(new_entry)
        db.session.commit()
        return redirect(url_for('passwords.home'))

    return render_template('add.html')


@passwords_bp.route("/generate-password", methods=["GET"])
@login_required
def generate_password_api():
    """API endpoint to generate a new password."""
    return jsonify(password=pass_generator())

@passwords_bp.route("/api/categories")
@login_required
def get_user_categories():
    """API endpoint to get all of the user's categories for autocomplete."""
    categories = db.session.execute(db.select(Category.name).where(Category.user_id == current_user.id)).scalars().all()
    return jsonify(categories)


@passwords_bp.route("/edit-password/<int:entry_id>", methods=["GET", "POST"])
@login_required
def edit_password(entry_id):
    entry = db.get_or_404(Passwords, entry_id)
    if entry.user_id != current_user.id:
        flash('Unauthorized access.', 'error')
        return redirect(url_for('passwords.home'))

    if request.method == "POST":
        form = request.form
        encrypted_payload = request.form.get("encrypted_payload")
        if not encrypted_payload:
            flash('Missing encrypted payload.', 'error')
            return render_template('edit.html', entry=entry)

        entry.encrypted_payload = encrypted_payload
        entry.site = None
        entry.username = None
        entry.password = None
        entry.additional_fields = None

        # Handle categories
        entry.categories.clear()
        category_names = [name.strip() for name in form.get('categories', '').split(',') if name.strip()]
        if category_names:
            for cat_name in category_names:
                category = db.session.execute(db.select(Category).where(
                    Category.user_id == current_user.id,
                    Category.name == cat_name
                )).scalar_one_or_none()
                if not category:
                    category = Category(name=cat_name, user_id=current_user.id)
                    db.session.add(category)
                entry.categories.append(category)

        entry.date_added = datetime.utcnow()  # Update timestamp when editing

        db.session.commit()
        flash('Password updated successfully!', 'success')
        return redirect(url_for('passwords.home'))

    return render_template('edit.html', entry=entry)


@passwords_bp.route("/delete/<int:entry_id>")
@login_required
def delete_entry(entry_id):
    entry_to_delete = db.get_or_404(Passwords, entry_id)
    if entry_to_delete.user_id == current_user.id:
        db.session.delete(entry_to_delete)
        db.session.commit()
    return redirect(url_for('passwords.home'))


@passwords_bp.route("/api/verify-account-password", methods=["POST"])
@login_required
@csrf.exempt
def verify_account_password():
    data = request.get_json(silent=True) or {}
    pwd = data.get("password", "")
    if not pwd or not check_password_hash(current_user.password, pwd):
        return jsonify({"ok": False}), 400
    return jsonify({"ok": True})


@passwords_bp.route("/bulk-delete", methods=["POST"])
@login_required
def bulk_delete():
    entry_ids_json = request.form.get('entry_ids')
    if not entry_ids_json:
        flash('No entries selected for deletion.', 'error')
        return redirect(url_for('passwords.home'))

    try:
        entry_ids = json.loads(entry_ids_json)
        deleted_count = db.session.query(Passwords).filter(
            Passwords.id.in_(entry_ids),
            Passwords.user_id == current_user.id
        ).delete(synchronize_session=False)
        db.session.commit()

        if deleted_count > 0:
            flash(f'Successfully deleted {deleted_count} password{"s" if deleted_count != 1 else ""}.', 'success')
    except Exception:
        db.session.rollback()
        flash('An error occurred while deleting passwords.', 'error')

    return redirect(url_for('passwords.home'))


@passwords_bp.route("/export/csv")
@login_required
def export_csv():
    entries = db.session.execute(db.select(Passwords).where(Passwords.user_id == current_user.id)).scalars().all()
    output = StringIO()
    writer = csv.writer(output)
    writer.writerow(['Id', 'EncryptedPayload', 'Categories'])

    for entry in entries:
        if not entry.encrypted_payload:
            continue
        writer.writerow([
            entry.id,
            entry.encrypted_payload,
            ";".join([c.name for c in entry.categories])
        ])

    output.seek(0)
    response = make_response(output.getvalue())
    response.headers['Content-Disposition'] = 'attachment; filename=passwords_export_encrypted.csv'
    response.headers['Content-Type'] = 'text/csv'
    return response


@passwords_bp.route("/export/json")
@login_required
def export_json():
    entries = db.session.execute(db.select(Passwords).where(Passwords.user_id == current_user.id)).scalars().all()
    export_data = {
        'exported_at': datetime.now().isoformat(),
        'passwords': [
            {
                'id': entry.id,
                'encrypted_payload': entry.encrypted_payload,
                'categories': [c.name for c in entry.categories],
                'date_added': entry.date_added.isoformat()
            } for entry in entries if entry.encrypted_payload
        ]
    }
    response = make_response(json.dumps(export_data, indent=2))
    response.headers['Content-Disposition'] = 'attachment; filename=passwords_export_encrypted.json'
    response.headers['Content-Type'] = 'application/json'
    return response


@passwords_bp.route("/import", methods=["GET", "POST"])
@login_required
def import_passwords():
    if request.method == "POST":
        if 'file' not in request.files or not request.files['file'].filename:
            flash('No file selected.', 'error')
            return redirect(request.url)
        file = request.files['file']
        if not file.filename.endswith('.json'):
            flash('Import now requires an encrypted JSON export.', 'error')
            return redirect(request.url)

        imported_count = 0
        error_count = 0

        try:
            json_data = json.loads(file.read().decode('utf-8'))
            records = json_data.get('passwords', [])

            for record in records:
                try:
                    encrypted_payload = record.get('encrypted_payload')
                    if not encrypted_payload:
                        error_count += 1
                        continue

                    # Categories remain optional metadata
                    category_names = record.get('categories', [])
                    password_categories = []
                    for cat_name in category_names:
                        category = db.session.execute(db.select(Category).where(
                            Category.user_id == current_user.id,
                            Category.name == cat_name
                        )).scalar_one_or_none()
                        if not category:
                            category = Category(name=cat_name, user_id=current_user.id)
                            db.session.add(category)
                        password_categories.append(category)

                    new_entry = Passwords(
                        site=None,
                        username=None,
                        password=None,
                        additional_fields=None,
                        favicon=None,
                        encrypted_payload=encrypted_payload,
                        user_id=current_user.id
                    )
                    new_entry.categories = password_categories
                    db.session.add(new_entry)
                    imported_count += 1
                except Exception:
                    error_count += 1
                    continue

            db.session.commit()
            flash(f'Imported {imported_count} encrypted records. {error_count} errors encountered.', 'success')
            return redirect(url_for('passwords.home'))
        except Exception as e:
            flash(f'Error importing file: {str(e)}', 'error')
            return redirect(request.url)

    return render_template('import.html')


@passwords_bp.route("/example")
def example():
    class ExampleEntry:
        def __init__(self, entry_id, site, username):
            self.id = entry_id
            self.site = site
            self.username = username

    all_examples = [
        (ExampleEntry(1, "Gmail"), "john.doe@gmail.com", "ExamplePass123!"),
        (ExampleEntry(2, "Facebook"), "johndoe@example.com", "SecureP@ssw0rd"),
        (ExampleEntry(3, "Twitter"), "@johndoe", "MyTw1tt3r!Pass"),
        (ExampleEntry(4, "LinkedIn"), "john.doe@example.com", "Pr0f3ssional#2024"),
    ]

    # Flatten the data for the template
    data_for_template = []
    for entry, username, password in all_examples:
        data_for_template.append((entry, password))

    # Filter out deleted examples
    deleted_ids = session.get('deleted_examples', [])
    example_data = [entry for entry in data_for_template if entry[0].id not in deleted_ids]

    return render_template('example.html', data=example_data)


@passwords_bp.route("/delete-example/<int:entry_id>")
def delete_example(entry_id):
    deleted_ids = session.get('deleted_examples', [])
    if entry_id not in deleted_ids:
        deleted_ids.append(entry_id)
    session['deleted_examples'] = deleted_ids
    return redirect(url_for('passwords.example'))
