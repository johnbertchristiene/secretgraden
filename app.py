import os
import hashlib
import base64
import binascii
import pytz
import uuid
from datetime import datetime
from flask import Flask, render_template, redirect, url_for, request, session, flash
from flask_sqlalchemy import SQLAlchemy
from sqlalchemy.sql import func
from werkzeug.utils import secure_filename
from textwrap import dedent

app = Flask(__name__)

# Set up the SQLite database
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///app.db'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
app.secret_key = os.urandom(24)

# Initialize the database
db = SQLAlchemy(app)

UPLOAD_FOLDER = os.path.join('static', 'uploads', 'n')
UPLOAD_COVER_PHOTO_FOLDER = os.path.join('static', 'uploads', 'cp')

os.makedirs(UPLOAD_FOLDER, exist_ok=True)
os.makedirs(UPLOAD_COVER_PHOTO_FOLDER, exist_ok=True)

# Define timezone before model definitions
philippines_tz = pytz.timezone('Asia/Manila')

# User model (representing the users table in the database)
class User(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(100), unique=True, nullable=False)
    password = db.Column(db.String(100), nullable=False)
    created_at = db.Column(db.DateTime, nullable=False, default=lambda: datetime.now(philippines_tz))  # Set Philippine Time on creation

class Category(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(100), nullable=False)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)

    def __repr__(self):
        return f'{self.name}'

class Note(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    title = db.Column(db.String(100), nullable=False)
    content = db.Column(db.Text, nullable=False)
    media = db.Column(db.String(100))  # Optional media field
    created_at = db.Column(db.DateTime, nullable=False, default=lambda: datetime.now(philippines_tz))  # Set Philippine Time on creation
    updated_at = db.Column(db.DateTime, nullable=False, default=lambda: datetime.now(philippines_tz), onupdate=lambda: datetime.now(philippines_tz))  # Set Philippine Time on update
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    user = db.relationship('User', backref=db.backref('notes', lazy=True)) 
    category_id = db.Column(db.Integer, db.ForeignKey('category.id'), nullable=True)
    category = db.relationship('Category', backref=db.backref('notes', lazy=True))
    is_deleted = db.Column(db.SmallInteger, nullable=False, default=0)  # 0: Not deleted, 1: Deleted, 2: Permanently Deleted
    date_deleted = db.Column(db.DateTime, nullable=True)

class CoverPhoto(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    filename = db.Column(db.String(255), nullable=False)
    uploaded_at = db.Column(db.DateTime, nullable=False, default=lambda: datetime.now(philippines_tz))  # Philippine time
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    user = db.relationship('User', backref=db.backref('cover_photos', lazy=True))

# Helper function to hash passwords
def hash_password(password):
    return hashlib.sha256(password.encode()).hexdigest()

# Routes
@app.route('/')
def index():
    if 'username' not in session:
        return redirect(url_for('login'))
    return redirect(url_for('profile'))

@app.route('/login', methods=['GET', 'POST'])
def login():
    if 'username' in session:
        return redirect(url_for('profile'))

    error_message = None
    username = ''
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']

        user = User.query.filter_by(username=username).first()
        if user and user.password == hash_password(password):
            session['username'] = username
            return redirect(url_for('profile'))
        else:
            error_message = "Login failed. Please check your credentials."

    return render_template('login.html', error_message=error_message, username=username)

@app.route('/signup', methods=['GET', 'POST'])
def signup():
    if 'username' in session:
        return redirect(url_for('profile'))

    error = None
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']

        if User.query.filter_by(username=username).first():
            error = "Username already exists."
        else:
            hashed_password = hash_password(password)
            new_user = User(username=username, password=hashed_password)
            db.session.add(new_user)
            db.session.commit()
            session['username'] = username
            return redirect(url_for('login'))

    return render_template('signup.html', error=error)

@app.route('/check_username', methods=['POST'])
def check_username():
    username = request.json.get('username')
    if User.query.filter_by(username=username).first():
        return {'exists': True}
    return {'exists': False}

@app.route('/logout')
def logout():
    session.pop('username', None)
    return redirect(url_for('login'))

@app.route('/profile')
def profile():
    if 'username' not in session:
        return redirect(url_for('login'))

    current_user = User.query.filter_by(username=session['username']).first()
    cover_photo = CoverPhoto.query.filter_by(user_id=current_user.id).order_by(CoverPhoto.id.desc()).first()

    # Fetch user notes where is_deleted is 0, ordered by most recent first
    user_notes = (
        Note.query
        .filter_by(user_id=current_user.id, is_deleted=0)
        .order_by(Note.created_at.desc())
        .all()
    )

    # Decrypt the title for each note
    decrypted_notes = []
    for note in user_notes:
        decrypted_title = decrypt_content_base64(note.title)
        decrypted_category_name = decrypt_content_base64(note.category.name) if note.category else None
        decrypted_notes.append({
            'note': note,
            'decrypted_title': decrypted_title,
            'decrypted_category_name': decrypted_category_name
        })

    # Check if there are any uncategorized notes (where category_id is None)
    uncategorized_notes = Note.query.filter_by(user_id=current_user.id, category_id=None, is_deleted=0).first()

    # Fetch and decrypt categories associated with non-deleted notes for the current user
    categories = [
        {
            'id': category.id,
            'encrypted_name': category.name,  # Encrypted value for the filter
            'decrypted_name': decrypt_content_base64(category.name)
        }
        for category in db.session.query(Category).join(Note).filter(
            Note.user_id == current_user.id,
            Note.is_deleted == 0,
            Category.id == Note.category_id
        ).distinct().all()
    ]


    # Check the session for delete success flag
    delete_success = session.pop('delete_success', False)  # Retrieve and remove the session flag

    return render_template(
        'profile.html',
        notes=decrypted_notes,
        categories=categories,
        cover_photo=cover_photo,
        delete_success=delete_success,  # Pass success flag
        uncategorized_notes=uncategorized_notes,
        username=current_user.username
    )

def generate_random_filename(filename):
    """Generate a random filename while preserving the file extension."""
    extension = os.path.splitext(filename)[1]
    return f"{uuid.uuid4().hex}{extension}"

@app.route('/upload_cover_photos', methods=['GET', 'POST'])
def upload_cover_photos():
    if 'username' not in session:
        return redirect(url_for('login'))

    message = None
    cover_photo = None

    # Fetch the current cover photo (from the database)
    user = User.query.filter_by(username=session['username']).first()
    cover_photo = CoverPhoto.query.filter_by(user_id=user.id).first()

    if request.method == 'POST':
        if 'cover_photo' in request.files:
            cover_photo_file = request.files['cover_photo']
            if cover_photo_file.filename != '':
                # Delete any existing cover photo for the user
                existing_photo = CoverPhoto.query.filter_by(user_id=user.id).first()
                if existing_photo:
                    file_path = os.path.join(UPLOAD_COVER_PHOTO_FOLDER, existing_photo.filename)
                    if os.path.exists(file_path):
                        os.remove(file_path)
                    db.session.delete(existing_photo)

                # Generate random filename
                filename = generate_random_filename(cover_photo_file.filename)
                save_path = os.path.join(UPLOAD_COVER_PHOTO_FOLDER, filename)
                cover_photo_file.save(save_path)

                # Save to database
                new_cover_photo = CoverPhoto(filename=filename, user_id=user.id)
                db.session.add(new_cover_photo)
                db.session.commit()

                message = "Cover photo uploaded successfully!"
            else:
                message = "No file selected. Please choose a file to upload."

    return render_template('upload_cover_photos.html', message=message, cover_photo=cover_photo)

@app.route('/delete_cover_photo/<int:photo_id>', methods=['POST'])
def delete_cover_photo(photo_id):
    photo = CoverPhoto.query.get(photo_id)
    if photo:
        # Delete the file from the uploads folder
        file_path = os.path.join(UPLOAD_COVER_PHOTO_FOLDER, photo.filename)
        if os.path.exists(file_path):
            os.remove(file_path)

        # Remove from database
        db.session.delete(photo)
        db.session.commit()

    return redirect(url_for('profile'))

@app.route('/settings', methods=['GET'])
def settings():
    if 'username' not in session:
        return redirect(url_for('login'))
    return render_template('settings.html')

@app.route('/update_password', methods=['POST'])
def update_password():
    if 'username' not in session:
        return redirect(url_for('login'))
    
    current_password = request.form['current_password']
    new_password = request.form['new_password']
    confirm_password = request.form['confirm_password']

    user = User.query.filter_by(username=session['username']).first()

    if not user or user.password != hash_password(current_password):
        return render_template('settings.html', error_message="Current password is incorrect.")

    if new_password != confirm_password:
        return render_template('settings.html', error_message="New passwords do not match.")

    user.password = hash_password(new_password)
    db.session.commit()

    return render_template('settings.html', success_message="Password updated successfully.")

BASE64_CHARS = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/"

def encrypt_content_base64(content):
    """Encrypt content using manual Base64 encoding."""
    content_bytes = content.encode('utf-8')  # Convert content to bytes
    encoded = []

    # Process bytes in chunks of 3
    for i in range(0, len(content_bytes), 3):
        chunk = content_bytes[i:i+3]
        padding = 3 - len(chunk)  # Calculate padding

        # Pad chunk with zero bytes if necessary
        chunk += b'\x00' * padding

        # Convert 3 bytes into 4 Base64 characters
        combined = (chunk[0] << 16) + (chunk[1] << 8) + chunk[2]
        encoded.append(BASE64_CHARS[(combined >> 18) & 0x3F])
        encoded.append(BASE64_CHARS[(combined >> 12) & 0x3F])
        encoded.append(BASE64_CHARS[(combined >> 6) & 0x3F])
        encoded.append(BASE64_CHARS[combined & 0x3F])

        # Replace padding characters with '='
        if padding:
            encoded[-padding:] = "=" * padding

    return "".join(encoded)

def decrypt_content_base64(base64_string):
    """Decrypt content using manual Base64 decoding."""
    base64_string = base64_string.strip()  # Remove surrounding whitespace
    padding_count = base64_string.count('=')  # Count padding
    base64_string = base64_string.rstrip('=')  # Remove padding characters for processing

    decoded = bytearray()

    # Process Base64 characters in chunks of 4
    for i in range(0, len(base64_string), 4):
        chunk = base64_string[i:i+4]
        combined = 0

        # Convert Base64 characters back to a 24-bit number
        for j, char in enumerate(chunk):
            if char in BASE64_CHARS:
                combined |= BASE64_CHARS.index(char) << (18 - 6 * j)

        # Extract up to 3 original bytes
        valid_bytes = (len(chunk) * 6) // 8  # Determine the number of valid bytes
        for j in range(valid_bytes):
            byte_position = (16 - j * 8)
            decoded.append((combined >> byte_position) & 0xFF)

    # Decode to UTF-8 and return the result
    try:
        return decoded.decode('utf-8')  # Convert bytes to a UTF-8 string
    except UnicodeDecodeError:
        return decoded  # Return raw bytes if decoding fails

@app.route('/add_note', methods=['GET', 'POST'])
def add_note():
    if 'username' not in session:
        return redirect(url_for('login'))

    current_user = User.query.filter_by(username=session['username']).first()

    if request.method == 'POST':
        title = request.form['title']
        content = request.form['content']
        category_name = request.form.get('category', '').strip().lower()

        # Encrypt title, content, and category name
        encrypted_title = encrypt_content_base64(title)
        encrypted_content = encrypt_content_base64(content)
        encrypted_category_name = encrypt_content_base64(category_name)

        # Handle category
        category = None
        if category_name:
            category = Category.query.filter(
                func.lower(Category.name) == func.lower(encrypted_category_name),
                Category.user_id == current_user.id
            ).first()
            if not category:
                category = Category(name=encrypted_category_name, user_id=current_user.id)
                db.session.add(category)
                db.session.commit()

        # Handle media upload
        media = request.files.get('media')
        media_filename = None
        if media and media.filename:
            media_filename = generate_random_filename(media.filename)
            media_path = os.path.join(UPLOAD_FOLDER, media_filename)
            os.makedirs(os.path.dirname(media_path), exist_ok=True)
            media.save(media_path)

        # Create the new note
        new_note = Note(
            title=encrypted_title,
            content=encrypted_content,
            category=category,
            media=media_filename,
            user_id=current_user.id
        )
        db.session.add(new_note)
        db.session.commit()

        return redirect(url_for('profile'))

    # Decrypt and fetch categories for the dropdown
    categories = [
        {
            'id': category.id,
            'name': decrypt_content_base64(category.name)
        }
        for category in db.session.query(Category).join(Note).filter(
            Note.user_id == current_user.id,
            Note.is_deleted == 0,
            Category.id == Note.category_id
        ).distinct().all()
    ]

    return render_template('add_note.html', categories=categories)


@app.route('/add_category', methods=['GET', 'POST'])
def add_category():
    if 'username' not in session:
        return redirect(url_for('login'))

    user = User.query.filter_by(username=session['username']).first()

    if request.method == 'POST':
        # Get and encrypt the category name
        category_name = request.form['category_name'].strip().lower()
        encrypted_category_name = encrypt_content_base64(category_name)

        # Create and add the new category
        new_category = Category(name=encrypted_category_name, user_id=user.id)
        print("Encrypted Category Name:", encrypted_category_name)
        db.session.add(new_category)
        db.session.commit()

        return redirect(url_for('add_note'))

    return render_template('add_category.html')

@app.route('/edit_note/<int:note_id>', methods=['GET', 'POST'])
def edit_note(note_id):
    if 'username' not in session:
        return redirect(url_for('login'))

    note = Note.query.get_or_404(note_id)
    current_user = User.query.filter_by(username=session['username']).first()

    if note.user_id != current_user.id or note.is_deleted != 0:
        return redirect(url_for('profile'))

    if request.method == 'POST':
        note.title = encrypt_content_base64(request.form['title'])
        note.content = encrypt_content_base64(request.form['content'])

        category_name = request.form['category'].strip().lower()
        if category_name:
            encrypted_category_name = encrypt_content_base64(category_name)
            category = Category.query.filter(
                func.lower(Category.name) == func.lower(encrypted_category_name),
                Category.user_id == current_user.id
            ).first()
            if not category:
                category = Category(name=encrypted_category_name, user_id=current_user.id)
                db.session.add(category)
                db.session.commit()
            note.category = category

        media = request.files.get('media')
        if media and media.filename:
            media_filename = generate_random_filename(media.filename)
            media_path = os.path.join('static/uploads/n', media_filename)
            os.makedirs(os.path.dirname(media_path), exist_ok=True)
            media.save(media_path)
            note.media = media_filename

        db.session.commit()
        return redirect(url_for('view_note', note_id=note.id))

    decrypted_title = decrypt_content_base64(note.title)
    decrypted_content = decrypt_content_base64(note.content)
    categories = [
        {
            'id': category.id,
            'name': decrypt_content_base64(category.name)
        }
        for category in db.session.query(Category).join(Note).filter(
            Note.user_id == current_user.id,
            Note.is_deleted == 0,
            Category.id == Note.category_id
        ).distinct().all()
    ]

    decrypted_category = None
    if note.category:
        decrypted_category = decrypt_content_base64(note.category.name)

    media_path = None
    if note.media:
        media_path = url_for('static', filename=f'uploads/n/{note.media}')

    return render_template(
        'edit_note.html',
        note=note,
        title=decrypted_title,
        category=decrypted_category,
        content=decrypted_content,
        categories=categories,
        media_path=media_path
    )

@app.route('/view_note/<int:note_id>')
def view_note(note_id):
    if 'username' not in session:
        return redirect(url_for('login'))

    # Get the logged-in user
    current_user = User.query.filter_by(username=session['username']).first()

    # Fetch the note
    note = Note.query.get_or_404(note_id)

    # Check if the note belongs to the current user
    if note.user_id != current_user.id or note.is_deleted != 0:
        return redirect(url_for('profile'))  # Redirect if unauthorized or note is deleted

    # Debug: Log the encrypted title
    print(f"Encrypted Title: {note.title}")

    # Decrypt content and title using Base64
    decrypted_content = decrypt_content_base64(note.content)
    decrypted_title = decrypt_content_base64(note.title)

    # Decrypt category if it exists
    decrypted_category = None
    if note.category:
        decrypted_category = decrypt_content_base64(note.category.name)

    # Debug: Log the decrypted title
    print(f"Decrypted Title: {decrypted_title}")

    philippines_tz = pytz.timezone('Asia/Manila')
    if note.created_at.tzinfo is None:
        note.created_at = philippines_tz.localize(note.created_at)  # Localize naive datetime to PHT
    
    formatted_date = note.created_at.strftime('%B %d, %Y %I:%M %p')  # Format the date for display

    # Handle media
    media_path = None
    if note.media:
        media_path = url_for('static', filename=f'uploads/n/{note.media}')

    print(f"Decrypted Title: {decrypted_title}")

    # Pass data to the template
    return render_template(
        'view_note.html',
        note=note,
        content=decrypted_content,
        title=decrypted_title,
        category=decrypted_category,
        media_path=media_path,
        note_id=note_id,
        formatted_date=formatted_date
    )

@app.route('/export_note/<int:note_id>')
def export_note(note_id):
    # Check if user is logged in
    if 'username' not in session:
        return redirect(url_for('login'))

    # Fetch the note for the logged-in user
    current_user = User.query.filter_by(username=session['username']).first()
    note = Note.query.filter_by(id=note_id, user_id=current_user.id, is_deleted=0).first()

    if not note:
        flash('Note not found or you do not have permission to export it.', 'danger')
        return redirect(url_for('profile'))

    # Decrypt the note title, category name, and content
    decrypted_title = decrypt_content_base64(note.title)
    decrypted_category_name = decrypt_content_base64(note.category.name) if note.category else 'Uncategorized'
    decrypted_content = decrypt_content_base64(note.content)

    if decrypted_content.startswith("Error:"):
        flash(decrypted_content, 'danger')
        return redirect(url_for('profile'))

    decrypted_content = decrypted_content.strip()

    # Prepare note content for the .txt file
    note_content = f"{decrypted_title}\n{decrypted_category_name}\n{note.created_at.strftime('%B %d, %Y %I:%M %p')}\n\n{decrypted_content}"

    # Generate a .txt file as a downloadable response
    response = app.response_class(
        response=note_content,
        status=200,
        mimetype='text/plain',
    )
    response.headers['Content-Disposition'] = f'attachment; filename="{decrypted_title}.txt"'
    return response


@app.route('/delete_note/<int:note_id>')
def delete_note(note_id):
    if 'username' not in session:
        return redirect(url_for('login'))

    note = Note.query.get_or_404(note_id)

    # Soft delete by updating the is_deleted field and setting date_deleted
    note.is_deleted = 1
    note.date_deleted = datetime.now(philippines_tz)
    db.session.commit()

    # Set a session flag indicating successful deletion
    session['delete_success'] = True

    # Redirect to the profile page
    return redirect(url_for('profile'))

@app.route('/compost_bin')
def compost_bin():
    # Check if user is logged in
    if 'username' not in session:
        return redirect(url_for('login'))

    current_user = User.query.filter_by(username=session['username']).first()

    # Fetch notes marked as deleted (is_deleted = 1) for the current user
    deleted_notes = (
        Note.query
        .filter_by(user_id=current_user.id, is_deleted=1)
        .order_by(Note.date_deleted.desc())
        .all()
    )

    # Decrypt titles and categories for deleted notes
    notes_with_decrypted_data = [
        {
            'note': note,
            'decrypted_title': decrypt_content_base64(note.title),
            'decrypted_category': decrypt_content_base64(note.category.name) if note.category else 'Uncategorized'
        }
        for note in deleted_notes
    ]

    return render_template(
        'compost_bin.html',
        notes=notes_with_decrypted_data,
        username=current_user.username
    )

@app.route('/restore_note/<int:note_id>')
def restore_note(note_id):
    if 'username' not in session:
        return redirect(url_for('login'))

    current_user = User.query.filter_by(username=session['username']).first()
    note = Note.query.filter_by(id=note_id, user_id=current_user.id, is_deleted=1).first()

    if not note:
        flash('Note not found or you do not have permission to restore it.', 'danger')
        return redirect(url_for('compost_bin'))

    note.is_deleted = 0
    note.date_deleted = None
    db.session.commit()

    flash('Note restored successfully.', 'success')
    return redirect(url_for('compost_bin'))

@app.route('/permanently_delete_note/<int:note_id>')
def permanently_delete_note(note_id):
    if 'username' not in session:
        return redirect(url_for('login'))

    current_user = User.query.filter_by(username=session['username']).first()
    note = Note.query.filter_by(id=note_id, user_id=current_user.id, is_deleted=1).first()

    if not note:
        flash('Note not found or you do not have permission to delete it.', 'danger')
        return redirect(url_for('compost_bin'))

    # Update is_deleted to 2 (permanently deleted)
    note.is_deleted = 2
    db.session.commit()

    flash('Note permanently deleted.', 'success')
    return redirect(url_for('compost_bin'))

if __name__ == '__main__':
    # Create the database tables
    with app.app_context():
        db.create_all()

    app.run(debug=True)
