from flask import Flask, render_template, request, redirect, url_for, session, flash, send_file, jsonify
import sqlite3
import bcrypt
import qrcode
import io
import os
from werkzeug.security import generate_password_hash, check_password_hash
import razorpay
import time
from flask_mail import Mail, Message
from flask_login import LoginManager, UserMixin, login_user, login_required, logout_user, current_user
from datetime import datetime, timedelta
import secrets
token = secrets.token_urlsafe(16)


app = Flask(__name__)
app.secret_key = 'your_secret_key'

# Mail configuration
app.config['MAIL_SERVER'] = 'smtp.gmail.com'
app.config['MAIL_PORT'] = 587
app.config['MAIL_USE_TLS'] = True
app.config['MAIL_USERNAME'] = 'techweldengineers@gmail.com'       # Your email
app.config['MAIL_PASSWORD'] = 'hsxy lacg trjy azjm'          # App password (not your Gmail password)
app.config['MAIL_DEFAULT_SENDER'] = 'techweldengineers@gmail.com'

mail = Mail(app)

def send_order_email(user_name, email, items, amount, address):
    msg = Message("🛒 New Order Received",
                  sender='techweldengineers@gmail.com',
                  recipients=['techweldengineers@gmail.com'])

    msg.body = f"""
    New Order Received

    👤 Name: {user_name}
    📧 Email: {email}
    
    📦 Items: {items}
    💰 Amount: ₹{amount}
    
    📍 Shipping Address:
    {address}
    """
    mail.send(msg)

def get_user_email(user_id):
    conn = get_db_connection()
    user = conn.execute("SELECT email FROM users WHERE id = ?", (user_id,)).fetchone()
    conn.close()
    return user['email'] if user else 'Unknown'
def send_mail(to, subject, body):
    msg = Message(subject, sender='techweldengineers@gmail.com', recipients=[to])
    msg.body = body
    mail.send(msg)



# Define the path to the SQLite database
basedir = os.path.abspath(os.path.dirname(__file__))
DATABASE = os.path.join(basedir, 'techweld.db')

# Function to get a database connection
def get_db_connection():
    conn = sqlite3.connect(DATABASE)
    conn.row_factory = sqlite3.Row
    return conn
RAZORPAY_KEY_ID = 'rzp_test_aAhXUWNLte2RJ5'
RAZORPAY_KEY_SECRET = 'XFiL2oD1raVoTdBfKgH6h4yQ'
razorpay_client = razorpay.Client(auth=(RAZORPAY_KEY_ID, RAZORPAY_KEY_SECRET))
razorpay_key=RAZORPAY_KEY_ID

login_manager = LoginManager()
login_manager.init_app(app)
login_manager.login_view = 'login' 

# --- ADMIN ROUTES START ---
@app.route('/admin/login', methods=['GET', 'POST'])
def admin_login():
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']
        if username == 'admin' and password == 'admin123':
            session['admin_logged_in'] = True
            return redirect(url_for('admin_dashboard'))
        else:
            flash('Invalid admin credentials')
    return render_template('admin_login.html')

@app.route('/admin/dashboard')
def admin_dashboard():
    if not session.get('admin_logged_in'):
        return redirect(url_for('admin_login'))
    conn = get_db_connection()
    products = conn.execute('SELECT * FROM products').fetchall()
    conn.close()
    return render_template('admin_dashboard.html', products=products)

@app.route('/admin/add_product', methods=['GET', 'POST'])
def add_product():
    if not session.get('admin_logged_in'):
        return redirect(url_for('admin_login'))

    if request.method == 'POST':
        name = request.form['name']
        price = int(request.form['price'])
        image = request.form['image']
        description = request.form['description']

        conn = get_db_connection()
        conn.execute('INSERT INTO products (name, price, image, description) VALUES (?, ?, ?, ?)',
                     (name, price, image, description))
        conn.commit()
        conn.close()
        flash('Product added!', 'success')
        return redirect(url_for('admin_dashboard'))

    return render_template('add_product.html')


class User(UserMixin):
    def __init__(self, user_data):
        self.id = user_data['id']
        self.username = user_data['username']
        self.email = user_data['email']
@login_manager.user_loader
def load_user(user_id):
    conn = get_db_connection()
    user = conn.execute('SELECT * FROM users WHERE id = ?', (user_id,)).fetchone()
    conn.close()
    if user:
        return User(user)
    return None
def get_user_by_id(user_id):
    conn = sqlite3.connect('techweld.db')
    cursor = conn.cursor()
    cursor.execute("SELECT username, email FROM users WHERE id = ?", (user_id,))
    row = cursor.fetchone()
    conn.close()
    return {'name': row[0], 'email': row[1]} if row else {'name': '', 'email': ''}
@app.route('/create_order', methods=['POST'])
def create_order():
    data = request.get_json()
    amount = data.get("amount", 50000)  # Default to ₹500

    try:
        order = razorpay_client.order.create({
            "amount": amount,  # amount in paise
            "currency": "INR",
            "payment_capture": 1
        })
        return jsonify({"order_id": order["id"], "amount": order["amount"]})
    except Exception as e:
        print("Error creating Razorpay order:", str(e))
        return jsonify({"error": "Failed to create order"}), 500

def get_cart_items(user_id):
    conn = get_db_connection()
    items = conn.execute('''
        SELECT 
            cart.product_id,
            cart.quantity,
            products.name,
            products.price
        FROM cart
        JOIN products ON cart.product_id = products.id
        WHERE cart.user_id = ?
    ''', (user_id,)).fetchall()
    conn.close()
    return items
def calculate_cart_total(cart_items):
    total = 0
    for item in cart_items:
        total += item['price'] * item['quantity']
    return total

def get_db_connection():
    conn = sqlite3.connect(DATABASE)
    conn.row_factory = sqlite3.Row
    return conn

def initialize_database():
    conn = get_db_connection()
    c = conn.cursor()

    # Create users table
    c.execute('''
        CREATE TABLE IF NOT EXISTS users (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            username TEXT NOT NULL,
            email TEXT NOT NULL UNIQUE,
            password TEXT NOT NULL

        )
    ''')

    # Create cart table
    c.execute('''
        CREATE TABLE IF NOT EXISTS cart (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            user_id INTEGER NOT NULL,
            product_id INTEGER NOT NULL,
            quantity INTEGER NOT NULL,
            FOREIGN KEY (user_id) REFERENCES users(id),
            FOREIGN KEY (product_id) REFERENCES products(id)
        )
    ''')

    # Create products table
    c.execute('''
        CREATE TABLE IF NOT EXISTS products (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            name TEXT NOT NULL,
            price INTEGER NOT NULL,
            image TEXT NOT NULL  -- Add this column for the image path
            description TEXT NOT NULL
        )
    ''')

    # Insert sample products if table is empty
    product_count = c.execute('SELECT COUNT(*) FROM products').fetchone()[0]
    if product_count == 0:
        sample_products = [
            ('X Machine MMA 260 II', 6000, 'pictures/product2.jpg', 'This is a high-quality MMA welding machine suitable for various industrial applications.'),
            ('X Machine', 5000, 'pictures/product1.png', 'A versatile welding machine ideal for all types of welding work.')
        ]
        c.executemany('INSERT INTO products (name, price, image, description) VALUES (?, ?, ?, ?)', sample_products)
    conn.commit()
    conn.close()
def get_all_products(category=None):
    db = get_db()
    cursor = db.cursor()

    if category:
        cursor.execute("SELECT * FROM products WHERE LOWER(category) = LOWER(?)", (category,))
    else:
        cursor.execute("SELECT * FROM products")

    return cursor.fetchall()

def get_product_by_id(product_id):
    conn = get_db_connection()
    product = conn.execute('SELECT * FROM products WHERE id = ?', (product_id,)).fetchone()
    conn.close()
    return product


@app.route('/')
def home():
    return render_template('home.html')
def get_all_products(category=None):
    conn = get_db_connection()
    if category:
        products = conn.execute('SELECT * FROM products WHERE category = ?', (category,)).fetchall()
    else:
        products = conn.execute('SELECT * FROM products').fetchall()
    conn.close()
    return products
@app.route('/products')
def products():
    category_name = request.args.get('category')
    print("Category filter received:", category_name)

    db = get_db_connection()
    products = []

    if category_name:
        cat = db.execute('SELECT id FROM categories WHERE name = ?', (category_name,)).fetchone()
        if cat:
            category_id = cat['id']
            print(f"Category ID found: {category_id}")
            products = db.execute('SELECT * FROM products WHERE category_id = ?', (category_id,)).fetchall()
            print(f"Number of products found: {len(products)}")
        else:
            print("No category found with that name.")
    else:
        products = db.execute('SELECT * FROM products').fetchall()
        print(f"No filter applied, total products: {len(products)}")

    return render_template('products.html', products=products, selected_category=category_name)
@app.route('/product/<int:product_id>')
def product_detail(product_id):
    conn = get_db_connection()
    product = conn.execute('SELECT * FROM products WHERE id = ?', (product_id,)).fetchone()
    conn.close()
    if product is None:
        return "Product not found", 404
    return render_template('product_detail.html', product=product)


@app.route('/about')
def about():
    return render_template('about.html')

@app.route('/contact')
def contact():
    return render_template('contact.html')
@app.route('/cart')
def cart():
    if 'user_id' not in session:
        flash('Please log in to view your cart.', 'warning')
        return redirect(url_for('login'))

    user_id = session['user_id']
    conn = get_db_connection()
    cart_items = conn.execute('SELECT * FROM cart WHERE user_id = ?', (user_id,)).fetchall()

    cart_details = []
    bag_total = 0
    total_discount = 0
    total_price = 0

    for item in cart_items:
        product = conn.execute('SELECT * FROM products WHERE id = ?', (item['product_id'],)).fetchone()
        if product:
            selling_price = product['price']
            # Check if 'original_price' column exists, else fallback to selling_price
            original_price = product['original_price'] if 'original_price' in product.keys() else selling_price

            quantity = item['quantity']
            item_total = selling_price * quantity
            item_savings = (original_price - selling_price) * quantity

            # Corrected: your column name is 'image', not 'image_url'
            image = product['image'] if 'image' in product.keys() else None

            cart_details.append({
                'product_id': product['id'],
                'name': product['name'],
                'price': selling_price,
                'original_price': original_price,
                'quantity': quantity,
                'savings': item_savings,
                'total_price': item_total,
                'image': image
            })

            bag_total += original_price * quantity
            total_discount += item_savings
            total_price += item_total

    conn.close()

    return render_template(
        'cart.html',
        cart_items=cart_details,
        total=total_price,
        total_original=bag_total,
        total_discount=total_discount,
        delivery_fee=0
    )

@app.route('/add_to_cart', methods=['POST'])
def add_to_cart():
    if 'user_id' not in session:
        flash('Please login first to add items to cart.', 'warning')
        return redirect(url_for('login'))
    
    product_id = request.form['product_id']
    quantity = int(request.form.get('quantity', 1))  # ✅ Read quantity from form
    user_id = session['user_id']

    conn = get_db_connection()
    c = conn.cursor()

    # Check if product already exists in the cart
    cart_item = c.execute('SELECT * FROM cart WHERE user_id = ? AND product_id = ?', (user_id, product_id)).fetchone()

    if cart_item:
        # ✅ Add selected quantity to existing quantity
        new_quantity = cart_item['quantity'] + quantity
        c.execute('UPDATE cart SET quantity = ? WHERE id = ?', (new_quantity, cart_item['id']))
    else:
        # ✅ Insert selected quantity
        c.execute('INSERT INTO cart (user_id, product_id, quantity) VALUES (?, ?, ?)', (user_id, product_id, quantity))

    conn.commit()
    conn.close()

    flash('Product added to cart!', 'success')
    return redirect(url_for('products'))

@app.route('/update_cart', methods=['POST'])
def update_cart():
    if 'user_id' not in session:
        flash('Please log in first.', 'warning')
        return redirect(url_for('login'))

    product_id = request.form['product_id']
    action = request.form['action']
    user_id = session['user_id']
    conn = get_db_connection()
    c = conn.cursor()
    cart_item = c.execute('SELECT * FROM cart WHERE user_id = ? AND product_id = ?', (user_id, product_id)).fetchone()
    if cart_item:
        quantity = cart_item['quantity']
        if action == 'increase':
            quantity += 1
        elif action == 'decrease' and quantity > 1:
            quantity -= 1
        c.execute('UPDATE cart SET quantity = ? WHERE id = ?', (quantity, cart_item['id']))
        conn.commit()
    conn.close()
    return redirect(url_for('cart'))

@app.route('/remove_from_cart', methods=['POST'])
def remove_from_cart():
    if 'user_id' not in session:
        flash('Please log in first.', 'warning')
        return redirect(url_for('login'))

    product_id = request.form['product_id']
    user_id = session['user_id']
    conn = get_db_connection()
    conn.execute('DELETE FROM cart WHERE user_id = ? AND product_id = ?', (user_id, product_id))
    conn.commit()
    conn.close()
    flash('Item removed from cart.', 'success')
    return redirect(url_for('cart'))

from flask import request, session, flash, redirect, url_for, render_template
from werkzeug.security import check_password_hash

@app.route('/login', methods=['GET', 'POST'])
def login():
    next_page = request.args.get('next')  # Optional redirect destination

    if request.method == 'POST':
        email = request.form['email']
        password = request.form['password']

        conn = get_db_connection()
        user = conn.execute('SELECT * FROM users WHERE email = ?', (email,)).fetchone()
        conn.close()

        if user:
            stored_hash = user['password']

            # Ensure stored_hash is a string
            if isinstance(stored_hash, bytes):
                stored_hash = stored_hash.decode('utf-8')

            # Optional: Print debug info
            # print("Stored hash:", stored_hash)

            if stored_hash and stored_hash.startswith('pbkdf2:sha256:'):  # Ensure it's from Werkzeug
                if check_password_hash(stored_hash, password):
                    session['user_id'] = user['id']
                    session['username'] = user['username']
                    flash('Logged in successfully!', 'success')
                    return redirect(next_page or url_for('home'))

        flash('Invalid email or password.', 'danger')

    return render_template('login.html')

@app.route('/register', methods=['GET', 'POST'])
def register():
    if request.method == 'POST':
        username = request.form['username']
        email = request.form['email']
        password = request.form['password']
        confirm_password = request.form['confirm_password']

        if password != confirm_password:
            return render_template('register.html', error='Passwords do not match.')

  
        # ✅ Generate password hash with pbkdf2 (compatible with Werkzeug)
        hashed_password = generate_password_hash(password, method='pbkdf2:sha256')

        conn = get_db_connection()
        try:
            conn.execute(
                'INSERT INTO users (username, email, password) VALUES (?, ?, ?)',
                (username, email, hashed_password)
            )
            conn.commit()
            flash('Registration successful! Please log in.', 'success')
            return redirect(url_for('login'))
        except sqlite3.IntegrityError:
            return render_template('register.html', error='Username or email already exists.')
        finally:
            conn.close()

    return render_template('register.html')
from flask import request, redirect, url_for, flash

from flask import session  # if you use session to track logged in user
@app.route('/checkout', methods=['GET', 'POST'])
def checkout():
    user_id = session.get('user_id')

    if not user_id:
        return redirect(url_for('login'))

    db = get_db_connection()

    if request.method == 'POST':
        saved_address_id = request.form.get('saved_address_id')
        name = request.form.get('full_name')
        phone = request.form.get('phone')
        pincode = request.form.get('pincode')
        street = request.form.get('street')
        city = request.form.get('city')
        state = request.form.get('state')
        country = request.form.get('country')

        # Case 1: User selected a saved address
        if saved_address_id:
            session['selected_address_id'] = saved_address_id  # Optional: store in session
            return redirect(url_for('payment'))

        # Case 2: User filled out a new address
        if name and phone and street and city and state and pincode and country:
            db.execute(
                '''INSERT INTO addresses (user_id, name, phone, address_line, city, state, pincode, country)
                   VALUES (?, ?, ?, ?, ?, ?, ?, ?)''',
                (user_id, name, phone, street, city, state, pincode, country)
            )
            db.commit()
            return redirect(url_for('payment'))

        # Case 3: Incomplete form
        error = "Please select a saved address or fill out all fields for a new address."
        saved_addresses = db.execute("SELECT * FROM addresses WHERE user_id = ?", (user_id,)).fetchall()
        return render_template('checkout.html', saved_addresses=saved_addresses, error=error)

    # GET request
    saved_addresses = db.execute("SELECT * FROM addresses WHERE user_id = ?", (user_id,)).fetchall()
    return render_template('checkout.html', saved_addresses=saved_addresses)


def calculate_order_total(cart_items):
    total = 0
    for item in cart_items:
        total += item['price'] * item['quantity']
    return total

def get_cart_items_for_user(user_id):
    conn = get_db_connection()
    query = '''
        SELECT p.id, p.name, p.price, c.quantity
        FROM cart c
        JOIN products p ON c.product_id = p.id
        WHERE c.user_id = ?
    '''
    cart_items = conn.execute(query, (user_id,)).fetchall()
    conn.close()
    return cart_items
def get_current_user():
    user_id = session.get('user_id')
    if not user_id:
        return None
    conn = get_db_connection()
    user = conn.execute('SELECT * FROM users WHERE id = ?', (user_id,)).fetchone()
    conn.close()
    return user
@app.route('/payment', methods=['GET', 'POST'])
def payment():
    user_id = session.get('user_id')
    if not user_id:
        return redirect(url_for('login'))

    cart_items = get_cart_items(user_id)
    amount = calculate_cart_total(cart_items)

    if request.method == 'POST':
        selected_method = request.form.get('payment_method')

        if selected_method == 'razorpay':
            order_amount = int(amount * 100)  # Convert to paise
            order_currency = 'INR'
            order_receipt = f"receipt_{user_id}_{int(time.time())}"

            razorpay_order = razorpay_client.order.create(dict(
                amount=order_amount,
                currency=order_currency,
                receipt=order_receipt,
                payment_capture=1
            ))

            return render_template('payment.html',
                selected_method='razorpay',
                razorpay_key_id=RAZORPAY_KEY_ID,
                razorpay_order_id=razorpay_order['id'],
                razorpay_amount=order_amount,
                name=get_user_by_id(user_id)['name'],
                email=get_user_by_id(user_id)['email'],
                amount=amount,
                cart_items=cart_items
            )

        elif selected_method == 'upi':
            return redirect(url_for('generate_payment_qr', amount=amount))

        elif selected_method == 'cod':
            return redirect(url_for('payment_success'))

        # Add other payment methods (card, wallet) as needed

    return render_template('payment.html', amount=amount, cart_items=cart_items, selected_method=None)
@app.route('/payment_success', methods=['POST'])
def payment_success():
    payment_id = request.form.get('razorpay_payment_id')
    order_id = request.form.get('razorpay_order_id')
    signature = request.form.get('razorpay_signature')

    user_id = session.get('user_id')
    user_name = session.get('username', 'Guest')

    if not user_id:
        flash("User not logged in.", "danger")
        return redirect(url_for('login'))

    conn = get_db_connection()

    # 1. Get user email
    user = conn.execute("SELECT email FROM users WHERE id = ?", (user_id,)).fetchone()
    user_email = user['email'] if user else 'guest@example.com'

    # 2. Get cart items with product names
    cart_items = conn.execute("""
        SELECT products.name AS product_name, cart.quantity
        FROM cart
        JOIN products ON cart.product_id = products.id
        WHERE cart.user_id = ?
    """, (user_id,)).fetchall()

    # 3. Calculate total amount
    total_amount = conn.execute("""
        SELECT SUM(products.price * cart.quantity)
        FROM cart
        JOIN products ON cart.product_id = products.id
        WHERE cart.user_id = ?
    """, (user_id,)).fetchone()[0] or 0

    # 4. Get latest address
    address = conn.execute("""
        SELECT * FROM addresses
        WHERE user_id = ?
        ORDER BY id DESC LIMIT 1
    """, (user_id,)).fetchone()

    # 5. Format cart items
    items = '\n'.join([f"• {item['product_name']} x{item['quantity']}" for item in cart_items])

    # 6. Format full address
    if address:
        address_str = f"""
{address['name']}
{address['address_line']}
{address['city']}, {address['state']} - {address['pincode']}
{address['country']}
📞 {address['phone']}
        """.strip()
    else:
        address_str = "No address provided."

    # 7. Insert into orders table
    order_date = datetime.now()
    expected_delivery = order_date + timedelta(days=5)

    conn.execute('''
        INSERT INTO orders (user_id, items, total_amount, order_date, expected_delivery, status)
        VALUES (?, ?, ?, ?, ?, ?)
    ''', (
        user_id, items, total_amount,
        order_date.strftime("%Y-%m-%d"),
        expected_delivery.strftime("%Y-%m-%d"),
        'Placed'
    ))
    conn.commit()
    conn.close()

    # 8. Send email to user
    user_msg = Message(
        subject='🧾 Order Confirmation - TechWeld Engineers',
        recipients=[user_email],
        body=f"""
Dear {user_name},

Thank you for your purchase! Your order has been successfully placed.

🛍️ Items:
{items}

💰 Total Amount: ₹{total_amount}

📦 Shipping Address:
{address_str}

🗓️ Order Date: {order_date.strftime('%Y-%m-%d')}
🚚 Expected Delivery: {expected_delivery.strftime('%Y-%m-%d')}

We’ll notify you once your order is shipped.

Thank you for shopping with TechWeld Engineers!

Best regards,  
Team TechWeld
        """
    )
    mail.send(user_msg)

    # 9. Send notification to TechWeld Engineers
    admin_msg = Message(
        subject='📬 New Order Placed - TechWeld Engineers',
        recipients=['techweldengineers@gmail.com'],
        body=f"""
Hey Team,

A new order has been placed by {user_name} ({user_email}).

🛒 Items:
{items}

💰 Amount: ₹{total_amount}

📍 Address:
{address_str}

🗓️ Order Date: {order_date.strftime('%Y-%m-%d')}
🚚 Expected Delivery: {expected_delivery.strftime('%Y-%m-%d')}

Check the admin dashboard or database for more info.

— Auto Notification System
        """
    )
    mail.send(admin_msg)

    flash("Payment successful! Order has been placed.", "success")
    return redirect(url_for('home'))
@app.route('/generate_payment_qr/<float:amount>')
def generate_payment_qr(amount):
    upi_id = "techweldengineers@upi"  # Replace with your real UPI ID
    qr_data = f"upi://pay?pa={upi_id}&pn=Weldon&am={amount:.2f}&cu=INR"
    
    # Generate QR Code
    img = qrcode.make(qr_data)
    buf = io.BytesIO()
    img.save(buf, format='PNG')
    buf.seek(0)
    
    return send_file(buf, mimetype='image/png')
@app.route('/admin/logout')
def admin_logout():
    session.pop('admin_logged_in', None)
    flash('Logged out successfully.')

@app.route('/admin/delete/<int:product_id>')
def delete_product(product_id):
    if not session.get('admin_logged_in'):
        return redirect(url_for('admin_login'))

    conn = get_db_connection()
    conn.execute('DELETE FROM products WHERE id = ?', (product_id,))
    conn.commit()
    conn.close()
    flash('Product deleted!', 'success')
    return redirect(url_for('admin_dashboard'))


@app.route('/admin/edit/<int:product_id>', methods=['GET', 'POST'])
def edit_product(product_id):
    if not session.get('admin_logged_in'):
        return redirect(url_for('admin_login'))

    conn = get_db_connection()
    product = conn.execute('SELECT * FROM products WHERE id = ?', (product_id,)).fetchone()

    if request.method == 'POST':
        name = request.form['name']
        price = int(request.form['price'])
        image = request.form['image']

        conn.execute('UPDATE products SET name = ?, price = ?, image = ? WHERE id = ?',
                     (name, price, image, product_id))
        conn.commit()
        conn.close()
        flash('Product updated!', 'success')
        return redirect(url_for('admin_dashboard'))

    conn.close()
    return render_template('edit_product.html', product=product)
    return render_template('profile.html', user=user, addresses=addresses, orders=orders)
@app.route('/cancel_order/<int:order_id>', methods=['POST'])
def cancel_order(order_id):
    user_id = session.get('user_id')
    if not user_id:
        flash("Please log in to cancel orders.", "danger")
        return redirect(url_for('login'))

    conn = get_db_connection()

    # Fetch the order
    order = conn.execute("SELECT * FROM orders WHERE id = ? AND user_id = ?", (order_id, user_id)).fetchone()

    if not order:
        conn.close()
        flash("Order not found or unauthorized.", "danger")
        return redirect(url_for('profile'))

    # Cancel the order
    conn.execute("UPDATE orders SET status = ? WHERE id = ?", ('Cancelled', order_id))
    conn.commit()

    # Get phone number from user's latest address
    address = conn.execute("SELECT phone FROM addresses WHERE user_id = ? ORDER BY id DESC LIMIT 1", (user_id,)).fetchone()
    phone_number = address['phone'] if address else 'Not available'

    # Get user email
    user = conn.execute("SELECT email FROM users WHERE id = ?", (user_id,)).fetchone()
    user_email = user['email'] if user else 'unknown@example.com'

    # Prepare email message
    subject = "🚫 Order Cancelled"
    msg_body = f"""
An order has been cancelled.

🧑 User: {session.get('username')}
📧 Email: {user_email}
📱 Phone: {phone_number}
🛒 Order ID: {order['id']}
📦 Items:
{order['items']}
💸 Amount: ₹{order['total_amount']}
🗓️ Order Date: {order['order_date']}

Please initiate the refund process to the original payment method or number.
    """.strip()

    # Send mail to TechWeld
    send_mail("techweldengineers@gmail.com", subject, msg_body)

    conn.close()
    flash("Order cancelled successfully. Refund (if any) will be processed soon.", "info")
    return redirect(url_for('profile'))

@app.route('/profile')
def profile():
    user_id = session.get('user_id')
    if not user_id:
        flash("Please log in to view your profile.", "danger")
        return redirect(url_for('login'))

    conn = get_db_connection()
    user = conn.execute("SELECT * FROM users WHERE id = ?", (user_id,)).fetchone()
    addresses = conn.execute("SELECT * FROM addresses WHERE user_id = ?", (user_id,)).fetchall()
    orders = conn.execute("SELECT * FROM orders WHERE user_id = ?", (user_id,)).fetchall()
    conn.close()

    return render_template('profile.html', user=user, addresses=addresses, orders=orders)


@app.route('/delete_address/<int:address_id>', methods=['POST'])
def delete_address(address_id):
    user_id = session.get('user_id')
    if not user_id:
        flash("Please log in to delete addresses.", "danger")
        return redirect(url_for('login'))

    conn = get_db_connection()
    conn.execute("DELETE FROM addresses WHERE id = ? AND user_id = ?", (address_id, user_id))
    conn.commit()
    conn.close()
    flash("Address deleted successfully.", "info")
    return redirect(url_for('profile'))
@app.route('/forgot_password', methods=['GET', 'POST'])
def forgot_password():
    if request.method == 'POST':
        email = request.form['email']

        conn = get_db_connection()
        user = conn.execute("SELECT * FROM users WHERE email = ?", (email,)).fetchone()

        if user:
            token = secrets.token_urlsafe(16)
            conn.execute("UPDATE users SET reset_token = ?, reset_token_expiry = ? WHERE id = ?",
                         (token, datetime.now().timestamp() + 3600, user['id']))
            conn.commit()
            conn.close()
            send_reset_email(email, token)
            flash("Reset link sent to your email.", "success")
        else:
            flash("Email not found.", "danger")

        return redirect(url_for('forgot_password'))

    return render_template('forgot_password.html')

def send_reset_email(to_email, token):
    reset_link = url_for('reset_password', token=token, _external=True)
    msg = Message("Reset Your TechWeldEngineers Password", recipients=[to_email])
    msg.body = f'''Hi there,

We received a request to reset your password.

Click the link below to set a new password:
{reset_link}

If you didn't request this, you can ignore this email.

Thanks,
TechWeld Engineers Team
'''
    mail.send(msg)
@app.route('/reset-password/<token>', methods=['GET', 'POST'])
def reset_password(token):
    conn = get_db_connection()
    user = conn.execute('SELECT * FROM users WHERE reset_token = ?', (token,)).fetchone()

    if not user:
        flash('Invalid or expired reset token.', 'danger')
        conn.close()
        return redirect(url_for('login'))

    expiry_str = user['reset_token_expiry']

    # Check if token has expired
    if expiry_str and datetime.fromtimestamp(float(expiry_str)) < datetime.now():
        flash('Reset token has expired.', 'danger')
        conn.close()
        return redirect(url_for('login'))

    if request.method == 'POST':
        new_password = request.form['new_password']
        confirm_password = request.form['confirm_password']

        if new_password != confirm_password:
            flash('Passwords do not match.', 'danger')
            conn.close()
            return render_template('reset_password.html')

        hashed = generate_password_hash(new_password, method='pbkdf2:sha256')

        print("Resetting password for user:", user)
        print("New hashed password:", hashed)

        conn.execute(
            'UPDATE users SET password = ?, reset_token = NULL, reset_token_expiry = NULL WHERE id = ?',
            (hashed, user['id'])
        )
        conn.commit()
        conn.close()

        flash('Password has been reset. You can now log in.', 'success')
        return redirect(url_for('login'))

    conn.close()
    return render_template('reset_password.html')
@app.route('/admin/users')
def list_users():
    users = User.query.all()
    users_data = [{'id': u.id, 'username': u.username, 'email': u.email} for u in users]
    return jsonify(users_data)
@app.route('/logout')
def logout():
    session.clear()
    flash('You have been logged out.', 'info')
    return redirect(url_for('home'))

if __name__ == '__main__':
    app.run(debug=True)
