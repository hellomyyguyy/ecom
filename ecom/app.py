from flask import Flask, render_template, request, redirect, url_for, session, flash
from flask_login import LoginManager, login_user, logout_user, login_required, current_user
from models import db, Product, User, CartItem, ProductVariant
from sqlalchemy.exc import OperationalError
from sqlalchemy import text
from werkzeug.security import generate_password_hash
from werkzeug.utils import secure_filename
import os
import logging

# Set up logging
logging.basicConfig(level=logging.DEBUG)
logger = logging.getLogger(__name__)

app = Flask(__name__,
            template_folder='templates',
            static_folder='static')
app.secret_key = 'your-secret-key'
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///' + os.path.join(os.path.abspath(os.path.dirname(__file__)),
                                                                    'store.db')
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
app.config['UPLOAD_FOLDER'] = os.path.join(os.path.abspath(os.path.dirname(__file__)), 'static', 'uploads')
app.config['ALLOWED_EXTENSIONS'] = {'png', 'jpg', 'jpeg', 'gif'}

app.jinja_env.add_extension('jinja2.ext.do')

db.init_app(app)

login_manager = LoginManager()
login_manager.init_app(app)
login_manager.login_view = 'login'

os.makedirs(app.config['UPLOAD_FOLDER'], exist_ok=True)


def allowed_file(filename):
    return '.' in filename and \
        filename.rsplit('.', 1)[1].lower() in app.config['ALLOWED_EXTENSIONS']


@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))


def update_user_schema():
    try:
        db.session.execute(text("SELECT password_hash FROM user LIMIT 1"))
        db.session.commit()
    except OperationalError:
        print("Updating User table schema from 'password' to 'password_hash'...")
        with app.app_context():
            db.session.execute(text("ALTER TABLE user ADD COLUMN password_hash TEXT"))
            users = db.session.execute(text("SELECT id, username, password FROM user")).fetchall()
            for user in users:
                user_id, username, old_password = user
                hashed_password = generate_password_hash(old_password)
                db.session.execute(
                    text("UPDATE user SET password_hash = :hash WHERE id = :id"),
                    {"hash": hashed_password, "id": user_id}
                )
            db.session.execute(text("ALTER TABLE user DROP COLUMN password"))
            db.session.commit()
        print("Schema updated successfully.")


with app.app_context():
    db.drop_all()
    db.create_all()
    update_user_schema()
    if not Product.query.first():
        tshirt = Product(
            name="T-Shirt",
            price=19.99,
            description="Cool cotton tee",
            image_filename=None,
            material=None,
            brand=None
        )
        mug = Product(
            name="Mug",
            price=9.99,
            description="Ceramic coffee mug",
            image_filename=None,
            material=None,
            brand=None
        )
        db.session.add_all([tshirt, mug])
        db.session.commit()

        db.session.add_all([
            ProductVariant(product_id=tshirt.id, size="S", color="Red", stock=2),
            ProductVariant(product_id=tshirt.id, size="M", color="Red", stock=2),
            ProductVariant(product_id=tshirt.id, size="L", color="Red", stock=2),
            ProductVariant(product_id=tshirt.id, size="S", color="Blue", stock=2),
            ProductVariant(product_id=tshirt.id, size="M", color="Blue", stock=0),
            ProductVariant(product_id=tshirt.id, size="L", color="Blue", stock=2),
        ])
        db.session.add_all([
            ProductVariant(product_id=mug.id, size=None, color="White", stock=10),
            ProductVariant(product_id=mug.id, size=None, color="Black", stock=0),
        ])
        db.session.commit()

        admin = User.query.filter_by(username='admin').first()
        if admin:
            admin.set_password('newpassword123')
            db.session.commit()
            print("Admin password reset to 'newpassword123'")
        else:
            admin = User(username='admin')
            admin.set_password('newpassword123')
            db.session.add(admin)
            db.session.commit()
            print("Admin user created with password 'newpassword123'")


@app.route('/')
def index():
    products = Product.query.all()
    # Render the template first, then clear the flag if it exists
    response = render_template('index.html', products=products)
    if session.get('incomplete_add_to_cart'):
        session.pop('incomplete_add_to_cart', None)
    return response


@app.route('/add_to_cart/<int:product_id>', methods=['POST'])
def add_to_cart(product_id):
    if 'user_id' not in session:
        session['user_id'] = 1
    product = Product.query.get_or_404(product_id)
    size = request.form.get('size')
    color = request.form.get('color')

    # Log the incoming request data
    logger.debug(f"Add to Cart Attempt - Product ID: {product_id}, Size: {size}, Color: {color}")

    # Check if product has both size and color options
    has_sizes = any(variant.size for variant in product.variants)
    has_colors = any(variant.color for variant in product.variants)
    logger.debug(f"Has Sizes: {has_sizes}, Has Colors: {has_colors}")

    # Validation for missing selections
    if has_sizes and (size == "N/A" or not size):
        session['incomplete_add_to_cart'] = True
        flash("Please pick a size.")
        logger.debug("Flashed: Please pick a size.")
        return redirect(url_for('index'))
    if has_colors and (color == "N/A" or not color):
        session['incomplete_add_to_cart'] = True
        flash("Please pick a color.")
        logger.debug("Flashed: Please pick a color.")
        return redirect(url_for('index'))

    # Find the variant matching the selected size and color
    variant = ProductVariant.query.filter_by(
        product_id=product_id,
        size=size if size and size != "N/A" else None,
        color=color if color and color != "N/A" else None
    ).first()

    if not variant:
        if not current_user.is_authenticated:
            session['incomplete_add_to_cart'] = True
            flash("Invalid size or color combination.")
            logger.debug("Flashed: Invalid size or color combination.")
        return redirect(url_for('index'))

    if variant.stock > 0:
        cart_item = CartItem.query.filter_by(
            user_id=session['user_id'],
            variant_id=variant.id
        ).first()
        if cart_item:
            cart_item.quantity += 1
        else:
            cart_item = CartItem(
                user_id=session['user_id'],
                variant_id=variant.id,
                quantity=1
            )
        variant.stock -= 1
        db.session.add(cart_item)
        db.session.commit()
        # Construct success message with product details
        success_message = f"{product.name}"
        if variant.size:
            success_message += f" {variant.size}"
        if variant.color:
            success_message += f" {variant.color}"
        success_message += " added to cart"
        flash(success_message)
        logger.debug(f"Flashed: {success_message}")
        # Clear the flag on successful add
        session.pop('incomplete_add_to_cart', None)
    else:
        if not current_user.is_authenticated:
            session['incomplete_add_to_cart'] = True
            flash("Selected variant is out of stock.")
            logger.debug("Flashed: Selected variant is out of stock.")
    return redirect(url_for('index'))


@app.route('/cart')
def cart():
    if 'user_id' not in session:
        session['user_id'] = 1
    cart_items = CartItem.query.filter_by(user_id=session['user_id']).all()
    cart_data = []
    total = 0
    for item in cart_items:
        variant = ProductVariant.query.get(item.variant_id)
        product = variant.product
        subtotal = item.quantity * product.price
        total += subtotal
        cart_data.append({
            'name': product.name,
            'quantity': item.quantity,
            'price': product.price,
            'subtotal': subtotal,
            'size': variant.size,
            'color': variant.color
        })
    return render_template('cart.html', cart_data=cart_data, total=total)


@app.route('/checkout', methods=['GET', 'POST'])
def checkout():
    if request.method == 'POST':
        CartItem.query.filter_by(user_id=session['user_id']).delete()
        db.session.commit()
        return redirect(url_for('index'))
    return render_template('checkout.html')


@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        username = request.form.get('username')
        password = request.form.get('password')
        user = User.query.filter_by(username=username).first()
        if user and user.check_password(password):
            login_user(user)
            return redirect(url_for('admin'))
        flash('Invalid username or password', 'login_error')
    return render_template('login.html')


@app.route('/logout')
@login_required
def logout():
    logout_user()
    return redirect(url_for('index'))


@app.route('/admin', methods=['GET', 'POST'])
@login_required
def admin():
    if request.method == 'POST':
        if 'product_id' in request.form and 'variant_id' in request.form:
            variant_id = request.form.get('variant_id')
            new_stock = request.form.get('stock')
            variant = ProductVariant.query.get_or_404(variant_id)
            try:
                variant.stock = int(new_stock)
                db.session.commit()
                flash(
                    f"Stock for {variant.product.name} (Size: {variant.size or 'N/A'}, Color: {variant.color}) updated to {variant.stock}!")
            except ValueError:
                flash("Please enter a valid number for stock.")
        elif 'new_name' in request.form:
            name = request.form.get('new_name')
            price = request.form.get('new_price')
            description = request.form.get('new_description')
            file = request.files.get('image')
            try:
                price = float(price)
                if price < 0:
                    raise ValueError("Price must be non-negative.")

                image_filename = None
                if file and allowed_file(file.filename):
                    filename = secure_filename(file.filename)
                    file.save(os.path.join(app.config['UPLOAD_FOLDER'], filename))
                    image_filename = filename

                material = request.form.get('material') if request.form.get('include_material') else None
                brand = request.form.get('brand') if request.form.get('include_brand') else None

                new_product = Product(
                    name=name,
                    price=price,
                    description=description,
                    image_filename=image_filename,
                    material=material,
                    brand=brand
                )
                db.session.add(new_product)
                db.session.flush()

                sizes = request.form.getlist('variant_size[]')
                colors = request.form.getlist('variant_color[]')
                stocks = request.form.getlist('variant_stock[]')
                logger.debug(f"Sizes: {sizes}, Colors: {colors}, Stocks: {stocks}")

                for size, color, stock in zip(sizes, colors, stocks):
                    if size.strip() or color.strip():
                        try:
                            stock_int = int(stock) if stock.strip() else 0
                            if stock_int < 0:
                                raise ValueError("Stock must be non-negative.")
                            variant = ProductVariant(
                                product_id=new_product.id,
                                size=size.strip() if size.strip() else None,
                                color=color.strip() if color.strip() else None,
                                stock=stock_int
                            )
                            db.session.add(variant)
                        except ValueError as e:
                            flash(
                                f"Invalid stock value for variant (Size: {size or 'N/A'}, Color: {color or 'N/A'}): {str(e)}")

                db.session.commit()
                flash(f"New product '{name}' added successfully!")
            except ValueError as e:
                db.session.rollback()
                flash(str(e))
        elif 'delete_product_id' in request.form:
            product_id = request.form.get('delete_product_id')
            product = Product.query.get_or_404(product_id)
            if product.image_filename:
                image_path = os.path.join(app.config['UPLOAD_FOLDER'], product.image_filename)
                if os.path.exists(image_path):
                    os.remove(image_path)
            db.session.delete(product)
            db.session.commit()
            flash(f"Product '{product.name}' deleted successfully!")
        return redirect(url_for('admin'))

    products = Product.query.all()
    return render_template('admin.html', products=products)


if __name__ == '__main__':
    app.run(debug=True)