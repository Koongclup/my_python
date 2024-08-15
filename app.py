from bson.objectid import ObjectId
from flask import Flask, render_template, request, redirect, url_for, flash, session
from flask_pymongo import PyMongo
from werkzeug.security import generate_password_hash, check_password_hash
from functools import wraps
from config import Config

app = Flask(__name__)
app.config.from_object(Config)
app.secret_key = 'your_secret_key'  # Replace with your actual secret key

mongo = PyMongo(app)
users_collection = mongo.db.users

def login_required(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if 'user_id' not in session:
            flash('You need to log in to access this page.', 'warning')
            return redirect(url_for('login'))
        return f(*args, **kwargs)
    return decorated_function

@app.route('/', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        email = request.form['email']
        password = request.form['password']
        user = mongo.db.users.find_one({'email': email})
        if user and check_password_hash(user['password'], password):  # Validate user credentials
            session['user_id'] = str(user['_id'])  # Store user ID in session
            flash('Login successful!', 'success')
            return redirect(url_for('dashboard'))
        flash('Invalid credentials, please try again.', 'danger')
    return render_template('login.html')

@app.route('/register', methods=['GET', 'POST'])
def register():
    if request.method == 'POST':
        name = request.form['name']
        email = request.form['email']
        password = request.form['password']
        
        # Check if user already exists
        if users_collection.find_one({"email": email}):
            flash('Email address already exists.', 'danger')
            return redirect(url_for('register'))
        
        # Hash the password using pbkdf2:sha256
        hashed_password = generate_password_hash(password, method='pbkdf2:sha256')
        
        # Insert the new user into the database
        users_collection.insert_one({'name': name, 'email': email, 'password': hashed_password})
        
        flash('Registration successful! Please log in.', 'success')
        return redirect(url_for('login'))
    
    return render_template('register.html')

@app.route('/dashboards')
@login_required
def dashboard():
    user = mongo.db.users.find_one({'_id': ObjectId(session['user_id'])})
    if not user:
        flash('User not found.', 'danger')
        return redirect(url_for('login'))
    return render_template('dashboards/index.html', user=user)

@app.route('/', methods=['POST'])
def logout():
    session.clear()  # Clear session data to log out the user
    flash('You have been logged out.', 'success')
    return redirect(url_for('login'))  # Redirect to the login page

@app.route('/users/')
@app.route('/users/page/<int:page>')
@login_required
def index(page=1):
    per_page = 5  # Number of users per page
    search_query = request.args.get('search', '')

    # Query the database with search and pagination
    query = {}
    if search_query:
        query = {'name': {'$regex': search_query, '$options': 'i'}}
    
    users_count = users_collection.count_documents(query)
    total_pages = (users_count + per_page - 1) // per_page
    users = users_collection.find(query).skip((page - 1) * per_page).limit(per_page)

    return render_template('users/index.html', users=users, page=page, total_pages=total_pages, search_query=search_query)

@app.route('/users/card')
@login_required
def card():
    # Pagination settings
    page = int(request.args.get('page', 1))
    per_page = 6
    total_users = users_collection.count_documents({})
    users = users_collection.find().skip((page - 1) * per_page).limit(per_page)
    
    total_pages = (total_users + per_page - 1) // per_page
    success = request.args.get('success')
    
    return render_template('users/card.html', users=users, success=success, page=page, total_pages=total_pages)

@app.route('/users/create', methods=['GET', 'POST'])
@login_required
def create_user():
    if request.method == 'POST':
        name = request.form['name']
        email = request.form['email']
        users_collection.insert_one({'name': name, 'email': email})
        return redirect(url_for('index', success='inserted'))
    return render_template('users/create_user.html')

@app.route('/users/update/<user_id>', methods=['GET', 'POST'])
@login_required
def update_user(user_id):
    user = users_collection.find_one({"_id": ObjectId(user_id)})
    if request.method == 'POST':
        name = request.form['name']
        email = request.form['email']
        users_collection.update_one(
            {"_id": ObjectId(user_id)},
            {"$set": {'name': name, 'email': email}}
        )
        return redirect(url_for('index', success='updated'))
    return render_template('users/update_user.html', user=user)

@app.route('/users/delete/<user_id>')
@login_required
def delete_user(user_id):
    users_collection.delete_one({"_id": ObjectId(user_id)})
    return redirect(url_for('index', success='deleted'))

if __name__ == '__main__':
    app.run(debug=True)
