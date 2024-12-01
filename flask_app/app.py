import os
import csv
from flask import Flask, render_template, redirect, url_for, flash, session, request, jsonify
from flask_pymongo import PyMongo
from flask_wtf import FlaskForm
from wtforms import StringField, PasswordField, EmailField, SubmitField
from wtforms.validators import DataRequired, Length, Email
from flask_login import LoginManager, UserMixin, login_user, login_required, logout_user, current_user
from werkzeug.security import generate_password_hash, check_password_hash
from bson import ObjectId
from werkzeug.utils import secure_filename
# Add near the top after imports
import logging
import sys

logging.basicConfig(
        level=logging.DEBUG,
    format='%(asctime)s %(levelname)s: %(message)s',
    handlers=[
        logging.FileHandler('/var/log/flavor-bomb/flask.log'),
        logging.StreamHandler(sys.stdout)
    ]
)

# Add before your first route
# Flask app setup
app = Flask(__name__)
app.config['MONGO_URI'] = "mongodb+srv://johnathanmoore9067:DDys44ia11@chefai.aqoz7.mongodb.net/chefai?retryWrites=true&w=majority&appName=ChefAI"
app.secret_key = 'your_secret_key'
mongo = PyMongo(app)

# Flask-Login setup
login_manager = LoginManager(app)
login_manager.login_view = 'login'

# Function to import ingredients from CSV to MongoDB
def import_ingredients_to_mongodb():
    # Path to the CSV file
    file_path = os.path.join(app.root_path, 'ingredients.csv')
    
    # Ensure the file exists
    if not os.path.exists(file_path):
        print("Error: ingredients.csv file not found!")
        return
    
    # Read and process the CSV file
    with open(file_path, newline='', encoding='utf-8') as csvfile:
        reader = csv.DictReader(csvfile)
        for row in reader:
            try:
                # Prepare ingredient data
                ingredient = {
                    'name': str(row.get('name', '')).strip(),
                    'type': str(row.get('type', '')).strip(),
                    'salty': int(row.get('salty', 0) or 0),
                    'sweet': int(row.get('sweet', 0) or 0),
                    'sour': int(row.get('sour', 0) or 0),
                    'bitter': int(row.get('bitter', 0) or 0),
                    'umami': int(row.get('umami', 0) or 0),
                    'preparation_techniques': str(row.get('preparation_techniques', '') or '').strip(),
                    'compatible_ingredients': str(row.get('compatible_ingredients', '') or '').strip(),
                    'highly_recommended': str(row.get('highly_recommended', '') or '').strip(),
                    'flavor_affinities': str(row.get('flavor_affinities', '') or '').strip()
                }
                
                # Skip invalid rows
                if not ingredient['name'] or not ingredient['type']:
                    print(f"Skipping invalid ingredient row: {row}")
                    continue
                
                # Upsert into MongoDB
                result = mongo.db.ingredients.update_one(
                    {'name': ingredient['name']},
                    {'$set': ingredient},
                    upsert=True
                )
                print(f"Upserted ingredient: {ingredient['name']} (matched {result.matched_count}, modified {result.modified_count})")
            except (ValueError, TypeError) as e:
                print(f"Error processing row {row}: {e}")

# User class for Flask-Login
class User(UserMixin):
    def __init__(self, user_id):
        self.id = user_id

@app.route('/test')
def test():
    return jsonify({
        'status': 'ok',
        'remote_addr': request.remote_addr,
        'headers': dict(request.headers)
    })

@app.route('/debug')
def debug():
    return {
        'remote_addr': request.remote_addr,
        'headers': dict(request.headers),
        'env': dict(request.environ)
    }

@login_manager.user_loader
def load_user(user_id):
    user_data = mongo.db.users.find_one({"_id": ObjectId(user_id)})
    if user_data:
        return User(str(user_data['_id']))
    return None

# Flask-WTF forms
class RegistrationForm(FlaskForm):
    first_name = StringField('First Name', validators=[DataRequired()])
    last_name = StringField('Last Name', validators=[DataRequired()])
    username = StringField('Username', validators=[DataRequired(), Length(min=4)])
    birthday = StringField('Birthday', validators=[DataRequired()])
    email = EmailField('Email', validators=[DataRequired(), Email()])
    password = PasswordField('Password', validators=[DataRequired(), Length(min=6)])
    submit = SubmitField('Register')

class LoginForm(FlaskForm):
    username_or_email = StringField('Username or Email', validators=[DataRequired()])
    password = PasswordField('Password', validators=[DataRequired()])
    submit = SubmitField('Login')

# Routes
@app.before_request
def log_request_info():
    app.logger.debug('Headers: %s', dict(request.headers))
    app.logger.debug('Remote addr: %s', request.remote_addr)
    app.logger.debug('URL: %s', request.url)

@app.route('/')
def landing():
    return render_template('landing.html')

@app.route('/register', methods=['GET', 'POST'])
def register():
    form = RegistrationForm()
    if form.validate_on_submit():
        hashed_password = generate_password_hash(form.password.data)
        mongo.db.users.insert_one({
            'first_name': form.first_name.data,
            'last_name': form.last_name.data,
            'username': form.username.data,
            'birthday': form.birthday.data,
            'email': form.email.data,
            'password': hashed_password
        })
        flash('Registration successful! Please log in.', 'success')
        return redirect(url_for('login'))
    return render_template('register.html', form=form)

@app.route('/login', methods=['GET', 'POST'])
def login():
    form = LoginForm()
    if form.validate_on_submit():
        user_data = mongo.db.users.find_one({
            '$or': [
                {'username': form.username_or_email.data},
                {'email': form.username_or_email.data}
            ]
        })
        if user_data and check_password_hash(user_data['password'], form.password.data):
            user = User(str(user_data['_id']))
            login_user(user)
            session['first_name'] = user_data['first_name']
            return redirect(url_for('own_profile'))
        else:
            flash('Invalid username/email or password.', 'danger')
    return render_template('login.html', form=form)

@app.route('/logout', methods=['POST'])
@login_required
def logout():
    logout_user()
    session.pop('first_name', None)
    flash('You have been logged out.', 'info')
    return redirect(url_for('landing'))

@app.route('/forums')
@login_required
def forums():
    return render_template('forums.html')

@app.route('/recipe_builder')
@login_required
def recipe_builder():
    return render_template('recipe_builder.html')

@app.route('/flavor_matrix')
@login_required
def flavor_matrix():
    ingredients = list(mongo.db.ingredients.find())
    for ingredient in ingredients:
        ingredient['_id'] = str(ingredient['_id'])  # Convert ObjectId to string
    return render_template('flavor_matrix.html', ingredients=ingredients)

@app.route('/edit_profile', methods=['GET', 'POST'])
@login_required
def edit_profile():
    user_data = mongo.db.users.find_one({"_id": ObjectId(current_user.id)})
    if request.method == 'POST':
        update_data = {
            "first_name": request.form['first_name'],
            "last_name": request.form['last_name'],
            "culinary_experience": request.form['culinary_experience'],
            "location": request.form['location'],
            "restaurant_or_school": request.form['restaurant_or_school'],
            "description": request.form['description']
        }
        if 'profile_picture' in request.files:
            file = request.files['profile_picture']
            if file:
                filename = secure_filename(file.filename)
                upload_folder = os.path.join(app.root_path, 'static/uploads')
                os.makedirs(upload_folder, exist_ok=True)
                filepath = os.path.join(upload_folder, filename)
                file.save(filepath)
                update_data["profile_picture"] = filename
        mongo.db.users.update_one({"_id": ObjectId(current_user.id)}, {"$set": update_data})
        flash("Profile updated successfully!", "success")
        return redirect(url_for('own_profile'))
    return render_template('edit_profile.html', user=user_data)

@app.route('/profile', methods=['GET'])
@login_required
def own_profile():
    user_data = mongo.db.users.find_one({"_id": ObjectId(current_user.id)})
    return render_template('profile.html', user=user_data, own_profile=True)

@app.route('/profile/<user_id>', methods=['GET'])
@login_required
def other_profile(user_id):
    if user_id == current_user.id:
        return redirect(url_for('own_profile'))
    user_data = mongo.db.users.find_one({"_id": ObjectId(user_id)})
    if not user_data:
        flash("User not found", "danger")
        return redirect(url_for('landing'))
    return render_template('profile.html', user=user_data, own_profile=False)

@app.route('/health')
def health_check():
    return 'OK', 200

if __name__ == '__main__':
    app.run()
