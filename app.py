from flask import Flask, render_template, request, redirect, url_for, jsonify, send_file
from flask_sqlalchemy import SQLAlchemy
from sqlalchemy.exc import IntegrityError
from flask_login import LoginManager, login_user, login_required, current_user, logout_user
import datetime
import os

app = Flask(__name__)
app.config['SECRET_KEY'] = '124551'
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///users.db'
db = SQLAlchemy(app)
login_manager = LoginManager(app)
login_manager.login_view = 'login'

class User(db.Model):
    id = db.Column(db.Integer, primary_key=True, autoincrement=True)
    username = db.Column(db.String(80), unique=True, nullable=False)
    password = db.Column(db.String(80), nullable=False)
    mac_address = db.Column(db.String(17))
    role = db.Column(db.String(20), default='user')
    is_banned = db.Column(db.Boolean, default=False)

    def is_authenticated(self):
        return True

    def is_active(self):
        return True

    def is_anonymous(self):
        return False

    def get_id(self):
        return str(self.id)

@login_manager.user_loader
def load_user(user_id):
    try:
        return User.query.get(int(user_id)) if user_id and user_id.isdigit() else None
    except ValueError:
        return None


start_time = datetime.datetime.now()


with app.app_context():
    db.create_all()
    default_user = User.query.filter_by(id=0).first()
    if not default_user:
        new_user = User(id=0, username='Viera', password='124551', mac_address='123', is_banned=False)
        db.session.add(new_user)
        db.session.commit()

@app.route('/')
@login_required
def index():
    if current_user.role == 'banned':
        return render_template('banned.html')
    
    if current_user.role != 'admin':
        return render_template('userpanel.html', user=current_user)
    users = User.query.all()
    return render_template('index.html', users=users)

@app.route('/userpanel')
@login_required
def userpanel():
    if current_user.role == 'banned':
        return render_template('banned.html')
    
    users = User.query.all()
    return render_template('userpanel.html', user=current_user)

@app.route('/login', methods=['POST', 'GET'])
def login():
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']
        user = User.query.filter_by(username=username, password=password).first()

        if user:
            if user.is_banned:
                return render_template('banned.html')

            login_user(user)

            if user.role == 'admin':
                return redirect(url_for('index'))
            else:
                login_user(user)
                return redirect(url_for('userpanel'))

    return render_template('login.html')

@app.route('/ban_user/<username>', methods=['POST'])
@login_required
def ban_user(username):
    if current_user.role != 'admin':
        return render_template('userpanel.html', user=current_user)
    
    user = User.query.filter_by(username=username).first()
    if user:
        user.role = 'banned'
        user.is_banned = True
        db.session.commit()
    return redirect(url_for('index'))

@app.route('/unban_user/<username>', methods=['POST'])
@login_required
def unban_user(username):
    if current_user.role != 'admin':
        return render_template('userpanel.html', user=current_user)
    
    user = User.query.filter_by(username=username).first()
    if user:
        user.role = 'user'
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
            login_user(user)
            return jsonify({"success": True, "message": "Login successful"})
        else:
            return jsonify({"success": False, "message": "Invalid credentials"})
    else:
        return jsonify({"success": False, "message": "Invalid credentials"})

@app.route('/logout')
@login_required
def logout():
    logout_user()
    return redirect(url_for('login'))

@app.route('/add_user', methods=['POST'])
@login_required
def add_user():
    if current_user.role != 'admin':
        return render_template('userpanel.html', user=current_user)
    
    username = request.form['username']
    password = request.form['password']
    mac_address = request.form['mac_address']

    new_user = User(username=username, password=password, mac_address=mac_address)
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
    if current_user.role != 'admin':
        return render_template('userpanel.html', user=current_user)
    
    user = User.query.filter_by(username=username).first()

    if user:
        db.session.delete(user)
        db.session.commit()

    return redirect(url_for('index'))

@app.route('/edit_user/<username>', methods=['GET', 'POST'])
@login_required
def edit_user(username):
    if current_user.role != 'admin':
        return render_template('userpanel.html', user=current_user)
    
    user = User.query.filter_by(username=username).first()

    if request.method == 'POST':
        if user:
            user.password = request.form['password']
            user.mac_address = request.form['mac_address']

            db.session.commit()
            return redirect(url_for('index'))

    return render_template('edit_user.html', username=username, user=user)

@app.route('/status')
@login_required
def status():
    if current_user.role == 'banned':
        return render_template('banned.html')
    
    uptime = datetime.datetime.now() - start_time
    return render_template('status.html', uptime=uptime, user=current_user)

@app.errorhandler(404)
def page_not_found(error):
    return render_template('404.html'), 404

@app.route('/version')
def version():
    latest_version = '1.1'
    download_url = 'https://sense.liara.run/download'
    
    return jsonify({
        'version': latest_version,
        'download_url': download_url
    })

@app.route('/download')
def download():
    file_path = os.path.join('dl', 'Sense.exe')
    return send_file(file_path, as_attachment=True)

if __name__ == '__main__':
    app.run(debug=True, host='0.0.0.0', port=int(os.getenv('LIARA_PORT', 8000)))
