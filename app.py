from flask import Flask, render_template, request, redirect, url_for, session, flash, jsonify
from flask_pymongo import PyMongo
import re
from werkzeug.security import generate_password_hash, check_password_hash
import pickle
import pandas as pd
from sklearn.preprocessing import StandardScaler
import shap
import numpy as np
from bson import ObjectId
from pymongo import MongoClient
from bson.objectid import ObjectId 


app = Flask(__name__)
app.secret_key = 'your_secret_key'

# 🔹 MongoDB Atlas Configuration
app.config["MONGO_URI"] = "mongodb+srv://niyacv13:niyaviju@cluster0.78z9j.mongodb.net/fetalstatus?retryWrites=true&w=majority&appName=Cluster0"
mongo = PyMongo(app)
db = mongo.db  # Get database reference

# 🔹 Ensure MongoDB is connected
if db is None:
    raise Exception("MongoDB connection failed!")


# Home Page
@app.route('/')
def home():
    return render_template('home.html')

# Registration Function
def register_user(role, template, redirect_url):
    if request.method == 'POST':
        username = request.form['username']
        email = request.form['email']
        phone = request.form['phone']
        password = request.form['password']
        
        # Check if the username, email, or phone already exists in the database
        users_collection = mongo.db.users
        
        # Check for existing username
        if users_collection.find_one({'username': username}):
            flash('Username already registered. Please choose a different one.', 'danger')
            print("Username already exists")  # Debugging line
        
        # Check for existing email
        elif users_collection.find_one({'email': email}):
            flash('Email is already registered. Please use a different email.', 'danger')
            print("Email already exists")  # Debugging line
        
        # Check for existing phone number
        elif users_collection.find_one({'phone': phone}):
            flash('Phone number is already registered. Please use a different phone number.', 'danger')
            print("Phone number already exists")  # Debugging line
        
        # Check for password length
        elif len(password) < 6:
            flash('Password must be at least 6 characters long', 'danger')
            print("Password validation failed")  # Debugging line
        
        else:
            # Insert the user into the database
            users_collection.insert_one({'username': username, 'email': email, 'phone': phone, 'password': password, 'role': role})
            flash('Registration successful! You can now login.', 'success')
            return redirect(url_for('login_user_route'))

    return render_template(template)

@app.route('/forgot_password', methods=['GET', 'POST'])
def forgot_password_user():
    if request.method == 'POST':
        username = request.form['username']
        new_password = request.form['new_password']
        
        # Check if the user exists in the database
        users_collection = mongo.db.users
        user = users_collection.find_one({'username': username})
        
        if user:
            # Update the password for the user
            users_collection.update_one(
                {'username': username},
                {'$set': {'password': new_password}}
            )
            flash('Password updated successfully. You can now login with your new password.', 'success')
            return redirect(url_for('login_user_route'))  # Redirect to login page
        else:
            flash('Username not found!', 'danger')
    
    return render_template('forgot_password.html')



def login_user(role, template, redirect_url):
    if request.method == 'POST':
        username = request.form['username']  # Get username instead of email
        password = request.form['password']
        
        # Search for the user by username and password
        users_collection = mongo.db.users
        user = users_collection.find_one({'username': username, 'password': password, 'role': role})
        
        if user:
            session['loggedin'] = True
            session['id'] = str(user['_id'])
            session['username'] = user['username']
            return redirect(url_for(redirect_url))
        else:
            flash('Invalid credentials', 'danger')
            print("Invalid login credentials")  # Debugging line

    return render_template(template)

# User Routes
@app.route('/register_user', methods=['GET', 'POST'])
def register_user_route():
    return register_user('user', 'register_user.html', 'login_user')

@app.route('/login_user', methods=['GET', 'POST'])
def login_user_route():
    return login_user('user', 'login_user.html', 'user_dashboard')



@app.route('/dashboard_user')
def user_dashboard():
    if 'loggedin' in session and 'username' in session:  # Ensure session contains username
        users_collection = mongo.db.users
        doctors_collection = mongo.db.doctors  # Reference to the doctors collection

        user = users_collection.find_one({'username': session['username']})

        doctor_name = "Unknown Doctor"  # Default value

        if user:
            # Ensure 'doctor_id' exists and is a valid ObjectId
            if 'doctor_id' in user and ObjectId.is_valid(user['doctor_id']):
                doctor = doctors_collection.find_one({'_id': ObjectId(user['doctor_id'])})
                if doctor:
                    doctor_name = doctor.get('name', "Unknown Doctor")

            return render_template(
                'dashboard_user.html',
                username=user.get('username', 'Unknown User'),
                prediction=user.get('prediction', None),
                probabilities=user.get('probabilities', []),  # Default to empty list if missing
                doctor_message=user.get('doctor_message', None),
                doctor_name=doctor_name  # Pass doctor name to template
            )

    flash("Please log in to access the dashboard.", "danger")
    return redirect(url_for('login_user'))



@app.route('/logout_user')
def logout_user():
    # Remove session data to log out the user
    session.pop('loggedin', None)
    session.pop('id', None)
    session.pop('username', None)
    
    
    return redirect(url_for('home'))  # Redirect to the login page


# Register Lab Assistant Route
def register_lab_assistant(role, template, redirect_url):
    if request.method == 'POST':
        username = request.form['username']
        email = request.form['email']
        phone = request.form['phone']
        password = request.form['password']
        
        # Check if the username, email, or phone already exists in the database
        lab_assistants_collection = mongo.db.lab_assistants
        
        # Check for existing username
        if lab_assistants_collection.find_one({'username': username}):
            flash('Username already registered. Please choose a different one.', 'danger')
            print("Username already exists")  # Debugging line
        
        # Check for existing email
        elif lab_assistants_collection.find_one({'email': email}):
            flash('Email is already registered. Please use a different email.', 'danger')
            print("Email already exists")  # Debugging line
        
        # Check for existing phone number
        elif lab_assistants_collection.find_one({'phone': phone}):
            flash('Phone number is already registered. Please use a different phone number.', 'danger')
            print("Phone number already exists")  # Debugging line
        
        # Check for password length
        elif len(password) < 6:
            flash('Password must be at least 6 characters long', 'danger')
            print("Password validation failed")  # Debugging line
        
        else:
            # Insert the lab assistant into the database
            lab_assistants_collection.insert_one({'username': username, 'email': email, 'phone': phone, 'password': password, 'role': role})
            flash('Registration successful! You can now login.', 'success')
            return redirect(url_for('login_lab_assistant_route'))  # Ensure this matches the correct route function

    return render_template(template)


#### 2. **Login Function for Lab Assistants**

def login_lab_assistant(role, template, redirect_url):
    if request.method == 'POST':
        username = request.form['username']  # Get username instead of email
        password = request.form['password']
        
        # Search for the lab assistant by username and password
        lab_assistants_collection = mongo.db.lab_assistants
        lab_assistant = lab_assistants_collection.find_one({'username': username, 'password': password, 'role': role})
        
        if lab_assistant:
            session['loggedin'] = True
            session['id'] = str(lab_assistant['_id'])
            session['username'] = lab_assistant['username']
            return redirect(url_for(redirect_url))  # Ensure redirect_url is passed and correct
        else:
            flash('Invalid credentials', 'danger')
            print("Invalid login credentials")  # Debugging line

    return render_template(template)

# Forgot Password Route
@app.route('/lab_forgot_password', methods=['GET', 'POST'])
def forgot_password_lab_assistant():
    if request.method == 'POST':
        username = request.form['username']
        new_password = request.form['new_password']
        
        # Find the lab assistant by username
        lab_assistants_collection = mongo.db.lab_assistants
        lab_assistant = lab_assistants_collection.find_one({'username': username})
        
        if lab_assistant:
            # Update the password with the new password
            lab_assistants_collection.update_one(
                {'username': username},
                {'$set': {'password': new_password}}
            )
            flash('Password updated successfully! You can now login with your new password.', 'success')
            return redirect(url_for('login_lab_assistant_route'))
        else:
            flash('Username not found. Please try again.', 'danger')
            print("Username not found")  # Debugging line

    return render_template('lab_forgot_password.html')



@app.route('/register_lab', methods=['GET', 'POST'])
def register_lab_assistant_route():
    return register_lab_assistant('lab_assistant', 'register_lab.html', 'login_lab_assistant_route')


@app.route('/login_lab', methods=['GET', 'POST'])
def login_lab_assistant_route():
    return login_lab_assistant('lab_assistant', 'login_lab.html', 'dashboard_lab')


@app.route('/dashboard_lab')
def dashboard_lab():
    if 'loggedin' in session:
        users_collection = mongo.db.users
        users = users_collection.find({'role': 'user'})  
        return render_template('dashboard_lab.html', users=users)
    else:
        flash('Please login to access the dashboard', 'danger')
        return redirect(url_for('login_lab_assistant_route'))

    

    
@app.route('/submit_test_values/<user_id>', methods=['POST'])
def submit_test_values(user_id):
    if 'loggedin' in session:
        users_collection = mongo.db.users
        user = users_collection.find_one({'_id': ObjectId(user_id)})

        if user:
            test_values = {feature: request.form[feature] for feature in request.form if feature != 'lab_assistant'}
            lab_assistant = request.form.get('lab_assistant')

            # Store values in the database and update status to 'Pending'
            users_collection.update_one(
                {'_id': ObjectId(user_id)},
                {'$set': {'test_values': test_values, 'lab_assistant': lab_assistant, 'status': 'Pending'}}
            )

            flash('Test values submitted successfully!', 'success')
            return redirect(url_for('dashboard_lab'))
        else:
            flash('User not found!', 'danger')
            return redirect(url_for('dashboard_lab'))
    else:
        flash('Please log in', 'danger')
        return redirect(url_for('login_lab_assistant_route'))
    

@app.route('/logout_lab')
def logout_lab_assistant():
    # Remove session data to log out the lab assistant
    session.pop('loggedin', None)
    session.pop('id', None)
    session.pop('username', None)
    
    flash('You have been logged out.', 'success')  # Optional flash message
    return redirect(url_for('home'))  # Redirect to the login page



@app.route('/login_doctor', methods=['GET', 'POST'])
def login_doctor():
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']

        # Validate the form data (check if username exists and password matches)
        doctor = mongo.db.doctors.find_one({'name': username})

        if doctor and doctor['password'] == password:
            session['loggedin'] = True
            session['username'] = doctor['name']
            session['email'] = doctor['email']  # Storing email as well, if needed for other operations
            flash('Login successful!', 'success')
            return redirect(url_for('dashboard_doctor'))
        else:
            flash('Invalid username or password, please try again.', 'danger')

    return render_template('login_doctor.html')



@app.route('/register_doctor', methods=['GET', 'POST'])
def register_doctor():
    if request.method == 'POST':
        name = request.form['name']
        email = request.form['email']
        password = request.form['password']

        # Validation: Check if email already exists
        if mongo.db.doctors.find_one({'email': email}):
            flash('Email is already registered. Please use a different email.', 'danger')
        elif len(password) < 6:
            flash('Password must be at least 6 characters long', 'danger')
        else:
            mongo.db.doctors.insert_one({'name': name, 'email': email, 'password': password})
            flash('Registration successful! You can now login.', 'success')
            return redirect(url_for('login_doctor'))

    return render_template('register_doctor.html')


@app.route('/dashboard_doctor')
def dashboard_doctor():
    if 'loggedin' in session:
        users_collection = mongo.db.users
        users = users_collection.find({'test_values': {'$exists': True}})

        # Convert MongoDB cursor to a list to ensure data is loaded
        users_list = list(users)

        return render_template('dashboard_doctor.html', users=users_list, username=session['username'])
    else:
        flash('Please login to access the dashboard', 'danger')
        return redirect(url_for('login_doctor'))


    
# Load trained model, scaler, and SHAP explainer
with open("fetal_ensemble_model.pkl", "rb") as model_file:
    ensemble_model = pickle.load(model_file)
with open("fetal_scaler.pkl", "rb") as scaler_file:
    scaler = pickle.load(scaler_file)
with open("fetal_shap_explainer.pkl", "rb") as shap_file:
    loaded_explainer = pickle.load(shap_file)

# Class label mapping
class_labels = {1: 'Normal', 2: 'Suspect', 3: 'Pathological'}

@app.route('/predict/<user_id>', methods=['POST'])
def predict(user_id):
    try:
        users_collection = mongo.db.users
        user = users_collection.find_one({'_id': ObjectId(user_id)})

        if not user or 'test_values' not in user:
            flash('No test values found for this user.', 'danger')
            return redirect(url_for('dashboard_doctor'))

        test_values = user['test_values']
        user_input = [float(test_values[key]) for key in test_values.keys()]  # Convert values to float

        # Ensure correct order of features
        columns = [
            'baseline value', 'accelerations', 'fetal_movement', 'uterine_contractions',
            'light_decelerations', 'severe_decelerations', 'prolongued_decelerations',
            'abnormal_short_term_variability', 'mean_value_of_short_term_variability',
            'percentage_of_time_with_abnormal_long_term_variability', 'mean_value_of_long_term_variability',
            'histogram_width', 'histogram_min', 'histogram_max', 'histogram_number_of_peaks',
            'histogram_number_of_zeroes', 'histogram_mode', 'histogram_mean', 'histogram_median',
            'histogram_variance', 'histogram_tendency'
        ]

        # Convert input into DataFrame
        new_data = pd.DataFrame([user_input], columns=columns)

        # Scale the input
        new_data_scaled = scaler.transform(new_data)

        # Predict the class using the ensemble model
        prediction = ensemble_model.predict(new_data_scaled)[0]  # Ensure correct class index
        predicted_class = prediction + 1  # Convert from 0-based to 1-based
        prediction_label = class_labels.get(predicted_class, "Unknown")

        # Get prediction probabilities
        prediction_probabilities = ensemble_model.predict_proba(new_data_scaled)[0].tolist()

        # Compute SHAP values
        shap_values = loaded_explainer.shap_values(new_data_scaled)

        # Compute mean SHAP importance
        mean_shap_values = np.abs(np.mean(shap_values, axis=0))
        shap_importance = sorted(zip(columns, mean_shap_values), key=lambda x: x[1], reverse=True)

        # Extract Top 3 Features
        top_3_features = shap_importance[:3]

        # ✅ **Update the user's document in MongoDB with prediction results**
        users_collection.update_one(
            {'_id': ObjectId(user_id)},
            {'$set': {
                'prediction': prediction_label,
                'probabilities': prediction_probabilities,
                'status': 'Predicted',
                'top_features': top_3_features
            }}
        )

        return render_template("predict_result.html",
                               username=user['username'],
                               phone=user['phone'],
                               prediction=prediction_label,
                               probabilities=prediction_probabilities,
                               shap_values=shap_importance,
                               top_features=top_3_features,
                               user_id=user_id)

    except Exception as e:
        return f"Error in prediction: {e}"

    
@app.route('/add_doctor_message/<user_id>', methods=['POST'])
def add_doctor_message(user_id):
    try:
        doctor_message = request.form.get('doctor_message')

        # Update MongoDB with doctor's message
        mongo.db.users.update_one(
            {'_id': ObjectId(user_id)},
            {'$set': {'doctor_message': doctor_message}}
        )

        flash('Doctor message saved successfully!', 'success')
        return redirect(url_for('home'))  # Redirect back to the doctor dashboard

    except Exception as e:
        return f"Error saving doctor message: {e}"


@app.route('/logout_doctor')
def logout_doctor():
    session.pop('loggedin', None)
    session.pop('username', None)
    session.pop('email', None)  # Or any other session variables you need to clear
    
    flash('You have been logged out successfully!', 'success')
    return redirect(url_for('home'))  # Redirect to the home page after logging out


# Logout
@app.route('/logout')
def logout():
    session.pop('loggedin', None)
    session.pop('id', None)
    session.pop('username', None)
    return redirect(url_for('home'))

if __name__ == '__main__':
    app.run(debug=True)
