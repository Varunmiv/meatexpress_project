import logging
from flask import Flask, render_template, redirect, url_for, request, flash, jsonify, session
from flask_sqlalchemy import SQLAlchemy
from flask_bcrypt import Bcrypt
from flask_login import LoginManager, login_user, logout_user, login_required, current_user, UserMixin
from flask_migrate import Migrate
from werkzeug.security import generate_password_hash, check_password_hash
import os
from datetime import datetime

basedir = os.path.abspath(os.path.dirname(__file__))



db = SQLAlchemy()
app = Flask(__name__)
app.config['SECRET_KEY'] = 'your_secret_key_here'
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///' + os.path.join(basedir, 'instance', 'database.db')
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
db.init_app(app)


def create_app():
    app = Flask(__name__)
    app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///' + os.path.join(basedir, 'instance', 'database.db')
    app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False

    db.init_app(app)

    # Import models and routes here, after initializing the app
    with app.app_context():
        from models import User
        db.create_all()

    return app
migrate = Migrate(app, db)
bcrypt = Bcrypt(app)
login_manager = LoginManager(app)
login_manager.login_view = 'login'

from forms import AdminLoginForm, LoginForm, SignupForm

# Configure logging
logging.basicConfig(level=logging.DEBUG)
logger = logging.getLogger(__name__)

# Log Bcrypt settings for debugging
logger.debug("Bcrypt settings: %s", bcrypt.__dict__)

class User(db.Model, UserMixin):
    id = db.Column(db.Integer, primary_key=True)
    email = db.Column(db.String(150), unique=True, nullable=False)
    name = db.Column(db.String(150), nullable=False)
    phone = db.Column(db.String(50), nullable=False)
    password_hash = db.Column(db.String(150), nullable=False)
    is_admin = db.Column(db.Boolean, default=False)

    def set_password(self, password):
        self.password_hash = bcrypt.generate_password_hash(password).decode('utf-8')

    def check_password(self, password):
        return bcrypt.check_password_hash(self.password_hash, password)

class Order(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    item_name = db.Column(db.String(150), nullable=False)
    quantity = db.Column(db.Integer, nullable=False)
    price = db.Column(db.Float, nullable=False)
    address = db.Column(db.String(250), nullable=True)
    mobile = db.Column(db.String(50), nullable=True)
    payment_method = db.Column(db.String(50), nullable=True)

class Admin(User):  # Use User class for Admin since Admin is a User with is_admin=True
    pass

class Booking(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    name = db.Column(db.String(100), nullable=False)
    email = db.Column(db.String(120), nullable=False)
    phone = db.Column(db.String(20), nullable=False)
    date = db.Column(db.DateTime, nullable=False, default=datetime.utcnow)
    special_request = db.Column(db.Text, nullable=True)

    def __repr__(self):
        return f'<Booking {self.name}>'

# Admin Login Route

@app.route('/admin_login', methods=['GET', 'POST'])
def admin_login():
    form = AdminLoginForm()
    if form.validate_on_submit():
        logging.debug("Admin login form submitted")
        admin = User.query.filter_by(email=form.email.data).first()
        logging.debug(f"Queried admin: {admin}")
        if admin:
            logging.debug("Admin found")
            if admin.check_password(form.password.data):
                logging.debug("Password correct")
                if admin.is_admin:
                    logging.debug("Admin flag is True")
                    login_user(admin)
                    session['user_type'] = 'admin'
                    flash('Admin login successful!', 'success')
                    return redirect(url_for('admin_dashboard'))
                else:
                    logging.debug("Admin flag is False")
            else:
                logging.debug("Password incorrect")
        else:
            logging.debug("Admin not found")
        flash('Invalid admin credentials.', 'danger')
    return render_template('admin_login.html', form=form)


@app.route('/admin_dashboard')
@login_required
def admin_dashboard():
    if not current_user.is_admin:
        flash('Unauthorized access', 'danger')
        return redirect(url_for('index'))

    users = User.query.all()
    orders = Order.query.all()
    return render_template('admin_dashboard.html', users=users, orders=orders)

@app.route('/admin/delete_user/<int:user_id>', methods=['POST'])
@login_required
def admin_delete_user(user_id):
    user = User.query.get(user_id)
    if user:
        db.session.delete(user)
        db.session.commit()
        flash('User deleted successfully', 'success')
    else:
        flash('User not found', 'danger')
    return redirect(url_for('admin_dashboard'))

@app.route('/admin/delete_order/<int:order_id>', methods=['POST'])
@login_required
def admin_delete_order(order_id):
    if not current_user.is_admin:
        flash('Unauthorized access', 'danger')
        return redirect(url_for('index'))

    order = Order.query.get(order_id)
    if order:
        db.session.delete(order)
        db.session.commit()
        flash('Order deleted successfully', 'success')
    else:
        flash('Order not found', 'danger')
    return redirect(url_for('admin_dashboard'))

# Add user_loader to the login manager
@login_manager.user_loader
def load_user(user_id):
    if session.get('user_type') == 'admin':
        return User.query.get(int(user_id))  # Admin is a User with is_admin=True
    return User.query.get(int(user_id))

@app.route('/')
def index():
    return render_template('index.html')

@app.route('/signup', methods=['GET', 'POST'])
def signup():
    form = SignupForm()
    if form.validate_on_submit():
        existing_user = User.query.filter_by(email=form.email.data).first()
        if existing_user:
            flash("User already exists!", "danger")
            return redirect(url_for('login'))

        hashed_password = bcrypt.generate_password_hash(form.password.data).decode('utf-8')
        new_user = User(email=form.email.data, name=form.name.data, phone=form.phone.data, password_hash=hashed_password)
        db.session.add(new_user)
        db.session.commit()
        flash('Account created successfully', 'success')
        return redirect(url_for('login'))
    return render_template('signup.html', form=form)

@app.route('/login', methods=['GET', 'POST'])
def login():
    form = LoginForm()
    if form.validate_on_submit():
        user = User.query.filter_by(email=form.email.data).first()
        if user and user.check_password(form.password.data):
            login_user(user, remember=form.remember.data)
            flash('Login successful!', 'success')
            return redirect(url_for('dashboard'))
        else:
            flash('Invalid email or password.', 'danger')
    return render_template('login.html', form=form)

@app.route('/dashboard')
@login_required
def dashboard():
    orders = Order.query.filter_by(user_id=current_user.id).all()
    return render_template('dashboard.html', user=current_user, orders=orders)

@app.route('/order_history')
def order_history():
    user_bookings = Booking.query.filter_by(user_id=current_user.id).all()
    return render_template('udashboard.html', bookings=user_bookings)


@app.route('/logout')
@login_required
def logout():
    logout_user()
    flash('You have been logged out', 'info')
    return redirect(url_for('index'))

@app.route('/place_order', methods=['POST'])
@login_required
def place_order():
    cart = request.json.get('cart', [])
    if not cart:
        return jsonify({"success": False, "message": "Your cart is empty."}), 400

    address = request.json.get('address')
    mobile = request.json.get('mobile')
    payment_method = request.json.get('payment_method', 'COD')

    try:
        for item in cart:
            new_order = Order(
                user_id=current_user.id,
                item_name=item['name'],
                quantity=item['quantity'],
                price=item['price'],
                address=address,
                mobile=mobile,
                payment_method=payment_method
            )
            db.session.add(new_order)
        db.session.commit()
        return jsonify({"success": True}), 200
    except Exception as e:
        db.session.rollback()
        return jsonify({"success": False, "message": str(e)}), 500

@app.route('/delete_order/<int:order_id>', methods=['POST'])
@login_required
def delete_order(order_id):
    order = Order.query.get(order_id)
    if order and order.user_id == current_user.id:
        db.session.delete(order)
        db.session.commit()
        flash('Order deleted successfully', 'success')
    else:
        flash('Order not found or unauthorized', 'danger')
    return redirect(url_for('dashboard'))

@app.route('/menu')
def menu():
    return render_template('menu.html')

@app.route('/about')
def about():
    return render_template('about.html')

@app.route('/more')
def more():
    return render_template('more.html')

@app.route('/book')
def book():
    return render_template('book.html')

@app.route('/book_now', methods=['POST'])
def book_now():
    name = request.form['name']
    email = request.form['email']
    phone = request.form['phone']
    special_request = request.form.get('special_request')

    new_booking = Booking(name=name, email=email, phone=phone, special_request=special_request)
    db.session.add(new_booking)
    db.session.commit()

    flash('Booking Successful!', 'success')
    return redirect(url_for('order_history'))

if __name__ == '__main__':
    # Create database tables
    with app.app_context():
        db.create_all()
        logger.debug("All tables created")

    # Run the Flask application
    app.run(debug=True, port=5001)
