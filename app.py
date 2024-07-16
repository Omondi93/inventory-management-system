from flask import Flask, render_template, request, redirect, url_for, flash
from flask_sqlalchemy import SQLAlchemy
from sqlalchemy import func
from datetime import datetime
from flask_login import LoginManager, UserMixin, login_user, login_required, logout_user, current_user
from werkzeug.security import generate_password_hash, check_password_hash

app = Flask(__name__)
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///inventory.db'
app.config['SECRET_KEY'] = 'your_secret_key_here'  # Change this to a random secret key
db = SQLAlchemy(app)
login_manager = LoginManager(app)
login_manager.login_view = 'login'

class User(UserMixin, db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(100), unique=True, nullable=False)
    password_hash = db.Column(db.String(200), nullable=False)

    def set_password(self, password):
        self.password_hash = generate_password_hash(password)

    def check_password(self, password):
        return check_password_hash(self.password_hash, password)

@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))

class Product(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(100), nullable=False)
    category = db.Column(db.String(50), nullable=False)
    quantity = db.Column(db.Integer, nullable=False)
    price = db.Column(db.Float, nullable=False)
    low_stock_threshold = db.Column(db.Integer, default=10)

@app.route('/')
@login_required
def index():
    return render_template('index.html')

@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        user = User.query.filter_by(username=request.form['username']).first()
        if user and user.check_password(request.form['password']):
            login_user(user)
            return redirect(url_for('index'))
        flash('Invalid username or password')
    return render_template('login.html')

@app.route('/logout')
@login_required
def logout():
    logout_user()
    return redirect(url_for('login'))

@app.route('/add_product', methods=['GET', 'POST'])
@login_required
def add_product():
    if request.method == 'POST':
        new_product = Product(
            name=request.form['name'],
            category=request.form['category'],
            quantity=int(request.form['quantity']),
            price=float(request.form['price']),
            low_stock_threshold=int(request.form['low_stock_threshold'])
        )
        db.session.add(new_product)
        db.session.commit()
        flash('Product added successfully')
        return redirect(url_for('index'))
    return render_template('add_product.html')

@app.route('/update_product/<int:id>', methods=['GET', 'POST'])
@login_required
def update_product(id):
    product = Product.query.get_or_404(id)
    if request.method == 'POST':
        product.name = request.form['name']
        product.category = request.form['category']
        product.quantity = int(request.form['quantity'])
        product.price = float(request.form['price'])
        product.low_stock_threshold = int(request.form['low_stock_threshold'])
        db.session.commit()
        flash('Product updated successfully')
        return redirect(url_for('index'))
    return render_template('update_product.html', product=product)

@app.route('/delete_product/<int:id>')
@login_required
def delete_product(id):
    product = Product.query.get_or_404(id)
    db.session.delete(product)
    db.session.commit()
    flash('Product deleted successfully')
    return redirect(url_for('index'))

@app.route('/search')
@login_required
def search_products():
    name = request.args.get('name', '')
    category = request.args.get('category', '')
    query = Product.query
    if name:
        query = query.filter(Product.name.ilike(f'%{name}%'))
    if category:
        query = query.filter(Product.category.ilike(f'%{category}%'))
    products = query.all()
    return render_template('search_results.html', products=products)

@app.route('/low_stock')
@login_required
def low_stock_alert():
    low_stock_products = Product.query.filter(Product.quantity <= Product.low_stock_threshold).all()
    return render_template('low_stock.html', products=low_stock_products)

@app.route('/report')
@login_required
def inventory_report():
    total_products = Product.query.count()
    total_value = db.session.query(func.sum(Product.quantity * Product.price)).scalar()
    low_stock_count = Product.query.filter(Product.quantity <= Product.low_stock_threshold).count()
    report = {
        'total_products': total_products,
        'total_inventory_value': total_value,
        'low_stock_products_count': low_stock_count,
        'report_generated_at': datetime.now().isoformat()
    }
    return render_template('report.html', report=report)

if __name__ == '__main__':
    with app.app_context():
        db.create_all()
        if not User.query.filter_by(username='admin').first():
            user = User(username='admin')
            user.set_password('password')
            db.session.add(user)
            db.session.commit()
    app.run(debug=True)