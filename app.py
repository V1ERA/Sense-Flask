from flask import Flask, render_template, request, redirect, url_for, jsonify, send_file, flash, session, make_response
from flask_sqlalchemy import SQLAlchemy
from sqlalchemy.exc import IntegrityError
from sqlalchemy import func
from flask_login import LoginManager, login_user, login_required, current_user, logout_user
from flask_limiter import Limiter
from flask_limiter.util import get_remote_address
from werkzeug.utils import secure_filename
from email_validator import validate_email, EmailNotValidError
import datetime
import random
import string
import os

app = Flask(__name__)
app.config['SECRET_KEY'] = '124551'
app.config['SQLALCHEMY_DATABASE_URI'] = 'mysql+mysqlconnector://root:124551@localhost:3306/sense'
app.config['UPLOAD_FOLDER'] = 'static/avatars'
ALLOWED_EXTENSIONS = {'jpg', 'jpeg', 'png'}

db = SQLAlchemy(app)
login_manager = LoginManager(app)
login_manager.login_view = 'login'

limiter = Limiter(key_func=get_remote_address)
limiter.init_app(app)

class User(db.Model):
    id = db.Column(db.Integer, primary_key=True, autoincrement=True)
    username = db.Column(db.String(80), unique=True, nullable=False)
    email = db.Column(db.String(80), unique=True, nullable=False)
    password = db.Column(db.String(80), nullable=False)
    mac_address = db.Column(db.String(17))
    role = db.Column(db.String(20), default='User')
    is_banned = db.Column(db.Boolean, default=False)
    profile_picture = db.Column(db.String(255), default='default.png')
    register_date = db.Column(db.DateTime, default=datetime.datetime.now)
    last_online = db.Column(db.DateTime)

    def is_authenticated(self):
        return True

    def is_active(self):
        return True

    def is_anonymous(self):
        return False

    def get_id(self):
        return str(self.id)
    
    @property
    def last_online_formatted(self):
        if self.last_online:
            return self.last_online.strftime('%Y/%m/%d %H:%M')
        
    @property
    def register_date_formatted(self):
        if self.register_date:
            return self.register_date.strftime('%Y/%m/%d %H:%M')

@login_manager.user_loader
def load_user(user_id):
    try:
        return User.query.get(int(user_id)) if user_id and user_id.isdigit() else None
    except ValueError:
        return None


start_time = datetime.datetime.now()


with app.app_context():
    db.create_all()

@app.before_request
def update_last_online():
    if current_user.is_authenticated:
        current_user.last_online = datetime.datetime.now()
        db.session.commit()

request_count = 0

def count_requests(func):
    def wrapper(*args, **kwargs):
        global request_count
        request_count += 1
        return func(*args, **kwargs)
    return wrapper

@app.route('/')
@count_requests
def index():
    if current_user.is_authenticated:
        return redirect(url_for('userpanel'))
    else:
        return redirect(url_for('register'))

@app.route('/adminpanel')
@login_required
def index():
    if current_user.role == 'Banned':
        return render_template('banned.html')
    
    if current_user.role != 'Administrator':
        return render_template('userpanel.html', user=current_user)
    users = User.query.all()
    return render_template('admin.html', users=users)

def generate_filename(user_id, filename):
    _, file_extension = os.path.splitext(filename)
    return f'avatar_{user_id}{file_extension}'

@app.route('/userpanel', methods=['GET', 'POST'])
@login_required
def userpanel():
    if current_user.role == 'Banned':
        return render_template('banned.html')

    users = User.query.all()

    if request.method == 'POST':
        if 'pfp' not in request.files:
            flash('No file part')
            return redirect(request.url)

        file = request.files['pfp']

        if file.filename == '':
            flash('No selected file')
            return redirect(request.url)

        if file and allowed_file(file.filename):
            filename = generate_filename(current_user.id, secure_filename(file.filename))
            
            os.makedirs(app.config['UPLOAD_FOLDER'], exist_ok=True)

            file.save(os.path.join(app.config['UPLOAD_FOLDER'], filename))

            current_user.profile_picture = filename
            db.session.commit()

            flash('Profile picture updated successfully')

    return render_template('userpanel.html', user=current_user, users=users)

def allowed_file(filename):
    return '.' in filename and filename.rsplit('.', 1)[1].lower() in ALLOWED_EXTENSIONS

@app.route('/users/<int:user_id>')
@login_required
def user_profile(user_id):
    viewed_user = User.query.get(user_id)

    if not viewed_user:
        return render_template('404.html'), 404

    return render_template('users.html', user=viewed_user, current_user=current_user)

@app.route('/register', methods=['POST', 'GET'])
@limiter.limit("3 per minutes")
def register():
    error = "Discord: https://discord.gg/gg8W2uFSqb"
    registered_username = "Unknown"

    if request.method == 'POST':
        username = request.form['username']
        email = request.form['email']
        password = request.form['password']
        ip_address = request.remote_addr

        if session.get('registered_ip') == ip_address:
            registered_username = session.get('registered_username')
            error = f"Please login as {registered_username}, Multi-Accounting is NOT allowed."

            return render_template('register.html', error=error, registered_username=registered_username)

        existing_user = User.query.filter_by(username=username).first()
        existing_email = User.query.filter_by(email=email).first()
        if existing_user or existing_email:
            return render_template('register.html', error="Already taken.")
        
        if len(password) < 8:
            return render_template('register.html', error=f"Password must be at least 8 characters long.")
        
        if len(username) < 5:
            return render_template('register.html', error=f"Username must be at least 5 characters long.")
        
        try:
            validate_email(email)
        except EmailNotValidError:
            return render_template('register.html', error="Invalid email address.")

        new_user = User(username=username, password=password, email=email, mac_address='Ask admin to set it for you.', role='Registered', register_date=datetime.datetime.now(), last_online=datetime.datetime.now(), is_banned=False, profile_picture='default.png')

        db.session.add(new_user)

        try:
            db.session.commit()
            login_user(new_user)
            
            session['registered_ip'] = ip_address
            session['registered_username'] = username
            
            return redirect(url_for('userpanel'))
        except IntegrityError:
            db.session.rollback()
            return render_template('register.html', error="Registration failed. Please try again.")

    return render_template('register.html', error=error, registered_username=registered_username)




@app.route('/login', methods=['POST', 'GET'])
@limiter.limit("3 per minute")
def login():
    error = "Discord: https://discord.gg/gg8W2uFSqb"

    if current_user.is_authenticated:
        if current_user.role == 'Administrator':
            return redirect(url_for('index'))
        else:
            return redirect(url_for('userpanel'))

    if request.method == 'POST':
        username = request.form['username'].lower()
        password = request.form['password']
        user = User.query.filter(func.lower(User.username) == username).first()

        if user and user.password == password:
            if user.is_banned:
                error = "Your account has been banned."
            else:
                login_user(user)
                if user.role == 'Administrator':
                    return redirect(url_for('index'))
                else:
                    return redirect(url_for('userpanel'))
        else:
            session.setdefault('login_attempts', 0)
            session['login_attempts'] += 1

            max_attempts = 4
            if session['login_attempts'] >= max_attempts:
                error = "Maximum login attempts exceeded."
                print(f"Maximum login attempts exceeded for username: {username}")
            else:
                error = "Invalid username or password."
                print(f"Invalid login attempt for username: {username}")

    return render_template('login.html', error=error)

@app.route('/ban_user/<username>', methods=['POST'])
@login_required
def ban_user(username):
    if current_user.role != 'Administrator':
        return render_template('userpanel.html', user=current_user)
    
    user = User.query.filter_by(username=username).first()
    if user:
        user.role = 'Banned'
        user.is_banned = True
        user.profile_picture = 'banned.png'
        db.session.commit()
    return redirect(url_for('index'))

@app.route('/unban_user/<username>', methods=['POST'])
@login_required
def unban_user(username):
    if current_user.role != 'Administrator':
        return render_template('userpanel.html', user=current_user)
    
    user = User.query.filter_by(username=username).first()
    if user:
        user.role = 'User'
        user.is_banned = False
        db.session.commit()
    return redirect(url_for('index'))

@app.route('/loginme', methods=['POST'])
def loginme():
    data = request.json
    username = data.get('username')
    password = data.get('password')
    provided_mac_address = data.get('mac_address')

    user = User.query.filter_by(username=username).first()

    if user:
        if user.is_banned:
            return jsonify({"success": False, "message": "User is banned"})
        elif user.password == password and user.mac_address == provided_mac_address:
            if user.role != 'Registered':
                login_user(user)
                return jsonify({"success": True, "message": "Login successful"})
            else:
                return jsonify({"success": False, "message": "User role is 'Registered'. Cannot login."})
        else:
            return jsonify({"success": False, "message": "Invalid credentials"})
    else:
        return jsonify({"success": False, "message": "Invalid credentials"})

@app.route('/logout')
@login_required
def logout():
    if current_user.role == 'Banned':
        return redirect(url_for('userpanel'))

    logout_user()
    return redirect(url_for('login'))

@app.route('/add_user', methods=['POST'])
@login_required
def add_user():
    if current_user.role != 'Administrator':
        return render_template('userpanel.html', user=current_user)
    
    username = request.form['username']
    email = request.form['email']
    password = request.form['password']
    mac_address = request.form['mac_address']

    new_user = User(username=username, password=password, email=email, mac_address=mac_address, register_date=datetime.datetime.now() ,last_online=datetime.datetime.now(), profile_picture='default.png')
    db.session.add(new_user)

    try:
        db.session.commit()
        return redirect(url_for('index'))
    except IntegrityError:
        db.session.rollback()
        return render_template('400.html'), 400

@app.route('/remove_user/<username>')
@login_required
def remove_user(username):
    if current_user.role != 'Administrator':
        return render_template('userpanel.html', user=current_user)
    
    user = User.query.filter_by(username=username).first()

    if user:
        db.session.delete(user)
        db.session.commit()

    return redirect(url_for('index'))

@app.route('/edit_user/<username>', methods=['GET', 'POST'])
@login_required
def edit_user(username):
    if current_user.role != 'Administrator':
        return render_template('userpanel.html', user=current_user)
    
    user = User.query.filter_by(username=username).first()

    if request.method == 'POST':
        if user:
            user.password = request.form['password']
            user.mac_address = request.form['mac_address']
            db.session.commit()
            return redirect(url_for('index'))

    return render_template('edit_user.html', username=username, user=user)

@app.route('/set_role/<username>', methods=['POST'])
@login_required
def set_role(username):
    if current_user.role != 'Administrator':
        return render_template('userpanel.html', user=current_user)

    user = User.query.filter_by(username=username).first()
    if user:
        new_role = request.form['role']
        user.role = new_role
        db.session.commit()

    return redirect(url_for('index'))

@app.route('/status')
@login_required
def status():
    
    uptime = datetime.datetime.now() - start_time
    return render_template('status.html', uptime=uptime, user=current_user)

@app.route('/users')
@login_required
def all_users():
    if current_user.role == 'Banned':
        return render_template('banned.html')
    
    users = User.query.all()
    return render_template('user_list.html', users=users)

@app.route('/login_as_user/<int:user_id>', methods=['POST'])
@login_required
def login_as_user(user_id):
    if current_user.role != 'Administrator':
        return render_template('userpanel.html', user=current_user)

    user = User.query.get(user_id)
    if user:
        login_user(user)

    flash('User not found.')
    return redirect(url_for('index'))


@app.errorhandler(404)
def page_not_found(error):
    return render_template('404.html'), 404

@app.errorhandler(429)
def page_not_found(error):
    return render_template('429.html'), 429

@app.route('/version')
def version():
    latest_version = '1.2'
    download_url = 'https://server.mastkhiar.xyz/download'
    
    return jsonify({
        'version': latest_version,
        'download_url': download_url
    })

@app.route('/download')
@limiter.limit("3 per minutes")
def download():
    file_path = os.path.join('dl', 'Sense.exe')
    return send_file(file_path, as_attachment=True)

@app.route('/stats')
def stats():
    return render_template('stats.html', request_count=request_count)

if __name__ == '__main__':
    app.run(debug=True, host='0.0.0.0', port=6969)