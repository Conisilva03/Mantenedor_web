from flask import Flask, render_template, request, jsonify, redirect, url_for, session, flash
from flask_cors import CORS
import requests
import jwt
from datetime import datetime, timedelta
from functools import wraps
import pytz 
from flask_paginate import Pagination, get_page_parameter
from flask_wtf.csrf import CSRFProtect
from forms import ParkingSpaceForm, LoginForm
import json

app = Flask(__name__)
CORS(app)  # Enable CORS to allow requests from the browser
csrf = CSRFProtect(app)
SECRET_KEY = "9a906627c7d4dac428f7ca952626b15e4cae78aa8f784527637f46ed5aba1eaa"
ALGORITHM = "HS512"
app.config['SECRET_KEY'] = SECRET_KEY  # Replace with a strong secret key
API_ESTACIONAMIENTOS ="https://api1.marweg.cl"
API_DATA = "http://0.0.0.0:8000"
csrf.init_app(app)

# Set the timezone to Chilean time (America/Santiago)
chilean_timezone = pytz.timezone('America/Santiago')

def get_user_id_from_session_cookie():
    token_value = session.get('jwt_token')
    if token_value:
        try:
            decoded_token = jwt.decode(token_value, SECRET_KEY, algorithms=[ALGORITHM])
            user_id = decoded_token.get('user_id')
            return user_id
        except jwt.ExpiredSignatureError as e:
            print("Expired Signature Error:", str(e))
            return None
        except jwt.InvalidTokenError as e:
            print("Invalid Token Error:", str(e))
            return None
        except Exception as e:
            print("Unexpected Error:", str(e))
            return None

    else:
        # Handle case where the "session" cookie is not present
        return None
    
# Protected route decorator
def protected_route(func):
    @wraps(func)
    def wrapper(*args, **kwargs):
        # Check if the user is authenticated
        jwt_token = session.get('jwt_token')
        if jwt_token is None:
            # User is not authenticated, redirect to the login page
            print('Please login to access this page.', 'info')
            return redirect('login')

        # Decode and verify the JWT token
        try:
            payload = jwt.decode(jwt_token, SECRET_KEY, algorithms=['HS512'])

            current_time = datetime.now(chilean_timezone)

            # Check if the token has expired
            if current_time > datetime.fromtimestamp(payload['exp'], chilean_timezone):
                print('Token has expired. Please login again.', 'info')
                return redirect('login')

            # User is authenticated and token is not expired, continue to the protected route
            return func(*args, **kwargs)
        except jwt.ExpiredSignatureError:
            print('Token has expired. Please login again.', 'info')
            return redirect('login')
        except jwt.InvalidTokenError:
            print('Invalid token. Please login again.', 'info')
            return redirect('login')

    return wrapper


@app.route('/')
@protected_route
def dashboard():
    access_token = session.get('jwt_token')
    token_type = "bearer"  # You can set the token type as needed
    # Fetch the user data from the FastAPI server
    user_id=get_user_id_from_session_cookie()
    api_url = f'{API_DATA}/{user_id}'
    
    headers = {
        'Authorization': f'Bearer {access_token}'  # Include the JWT token in the request headers
    }

    response = requests.get(api_url, headers=headers)

    print(response.json())
    if response.status_code == 200:
        user_data = response.json()
        username = user_data.get('username')  # Extract the username
        # Now you can use the username in your template or perform any required actions

        return render_template('index.html', access_token=access_token, token_type=token_type, current_user=username)

    # Handle the case when the request to the FastAPI server fails
    print('Failed to fetch user data.', 'error')
    return render_template('index.html', access_token=access_token, token_type=token_type)


@app.route('/login', methods=['GET', 'POST'])
def login():
    form = LoginForm()
    if request.method == 'POST':
        if form.validate_on_submit():
            # Get the form data
            username = request.form['username']
            password = request.form['password']
    
            # Perform form validation (add more validation as needed)
            if not username or not password:
                print('Username and password are required.', 'error')
                return render_template('login.html',form=form)
    
            # Prepare the data for the POST request
            data = {
                'username': username,
                'password': password
            }
    
            # Make the POST request to the API
            api_url = f'{API_DATA}/login'
            response = requests.post(api_url, data=data, headers={'Content-Type': 'application/x-www-form-urlencoded'})
    
            if response.status_code == 200:
                # Parse the JSON response content
                try:
                    response_data = response.json()
                    access_token = response_data.get('access_token')
                    token_type = response_data.get('token_type')
                    # Set the session cookie
                    session['jwt_token'] = access_token
    
    
                    # Redirect to the dashboard
                    print('Login successful!', 'success')
                    return redirect('/')
                except ValueError:
                    print('Invalid JSON response from the API.', 'error')
                    return render_template('login.html',form=form)

    # If it's a GET request or if login fails, render the login form
    return render_template('login.html',form=form)

@app.route('/logout')
def logout():
    # Remove the 'jwt_token' from the session to log the user out
    session.pop('jwt_token', None)
    
    # Redirect to the login page or any other desired page
    return redirect(('login'))

# Number of users per page
PER_PAGE = 10


@app.route('/usuarios')
@protected_route
def user_list():
    page = request.args.get(get_page_parameter(), type=int, default=1)
    offset = (page - 1) * PER_PAGE
    
    access_token = session.get('jwt_token')
    user_id = get_user_id_from_session_cookie()
    print(access_token)
    
    user_data = fetch_user_data(access_token)
    c_user_data = fetch_current_user_data(access_token, user_id)

    users_on_page = user_data[offset:offset + PER_PAGE]
    total = len(user_data)

    pagination = Pagination(page=page, total=total, per_page=PER_PAGE)

    return render_template('listUsers.html', users=users_on_page, pagination=pagination, current_user=c_user_data)

def fetch_parking_data(access_token):
    api_url = f'{API_ESTACIONAMIENTOS}/parking_spaces/'
    
    headers = {
        'Authorization': f'Bearer {access_token}'  # Include the JWT token in the request headers
    }

    response = requests.get(api_url, headers=headers)

    if response.status_code == 200:
        parking_data = response.json()
    else:
        parking_data = []

    return parking_data

def post_parking_space( name, location,description, latitude, longitude, state):
    access_token = session.get('jwt_token')

    api_url = f'{API_ESTACIONAMIENTOS}/parking_spaces/'
    
    headers = {
        'Authorization': f'Bearer {access_token}',
        'Content-Type': 'application/json'  # Set the content type to JSON
    }

    # Create a dictionary with the data to be posted
    parking_space_data = {
        'id':'0',
        'name': name,
        'location': location,
        'description':description,
        'latitude': latitude,
        'longitude': longitude,
        'state': state
    }

    # Convert the data to JSON format
    json_data = json.dumps(parking_space_data)

    response = requests.post(api_url, data=json_data, headers=headers)
    if response.status_code == 200:
        # The resource was successfully created
        parking_space = response.json()
        return parking_space
    else:
        # Handle the error case here
        return None


def fetch_user_data(access_token):
    api_url = f'{API_DATA}/users/'
    
    headers = {
        'Authorization': f'Bearer {access_token}'  # Include the JWT token in the request headers
    }

    response = requests.get(api_url, headers=headers)

    if response.status_code == 200:
        user_data = response.json()
    else:
        user_data = []

    return user_data

def fetch_current_user_data(access_token, user_id):
    c_user_api_url = f'{API_DATA}/users/{user_id}'
    
    headers = {
        'Authorization': f'Bearer {access_token}'  # Include the JWT token in the request headers
    }

    response = requests.get(c_user_api_url, headers=headers)

    if response.status_code == 200:
        c_user_user_data = response.json()
        current_user = c_user_user_data.get('username')
    else:
        current_user = None

    return current_user

@app.route('/lista_estacionamientos')
@protected_route
def parking_spaces():
    access_token = session.get('jwt_token')
    parking_space_data = fetch_parking_data(access_token)

    # You can also implement pagination logic here

    per_page = 10  # Number of items per page
    total = len(parking_space_data)  # Total number of items
    page = request.args.get('page', type=int, default=1)  # Get the current page from the request

    pagination = Pagination(page=page, per_page=per_page, total=total, bs_version=4)

    return render_template('listParking.html', parking_space_data=parking_space_data, pagination=pagination)


@app.route('/agregar_estacionamiento', methods=['GET', 'POST'])
def add_parking_space():
    access_token = session.get('jwt_token')

    form = ParkingSpaceForm()

    if form.validate_on_submit():
        # Create a new parking space based on the form data
        parking_space = {
            'name': form.name.data,
            'location': form.location.data,
            'description':form.description.data,
            'latitude': form.latitude.data,
            'longitude': form.longitude.data,
            'state': form.state.data,
        }
        name = form.name.data
        location = form.location.data
        description = form.description.data
        latitude = form.latitude.data
        longitude = form.longitude.data
        state = form.state.data
        
        result = post_parking_space( name, location,description, latitude, longitude, state)

        # Redirect to the parking spaces list page
        return redirect(url_for('parking_spaces'))

    return render_template('newParking.html', form=form)


if __name__ == '__main__':
    app.run(debug=True)
