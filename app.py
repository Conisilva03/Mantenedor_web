from flask import Flask, render_template, request, jsonify, redirect, url_for, session, flash, Response
from reportlab.pdfgen import canvas
import io
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
from flask import flash, get_flashed_messages
from reportlab.lib.pagesizes import letter



app = Flask(__name__)
CORS(app)  # Enable CORS to allow requests from the browser
csrf = CSRFProtect(app)
SECRET_KEY = "9a906627c7d4dac428f7ca952626b15e4cae78aa8f784527637f46ed5aba1eaa"
ALGORITHM = "HS512"
app.config['SECRET_KEY'] = SECRET_KEY  # Replace with a strong secret key
API_ESTACIONAMIENTOS ="https://api1.marweg.cl"
API_DATA = "https://api2.parkingtalcahuano.cl"
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


def fetch_parking_data(access_token):
    api_url = f'{API_ESTACIONAMIENTOS}/parking_spaces/'
    
    headers = {
        'Authorization': f'Bearer {access_token}' 
    }

    response = requests.get(api_url, headers=headers)

    if response.status_code == 200:
        parking_data = response.json()
    else:
        parking_data = []

    return parking_data


def fetch_reservas_data(access_token):
    api_url = f'{API_DATA}/reservations'
    
    headers = {
        'Authorization': f'Bearer {access_token}' 
    }

    response = requests.get(api_url, headers=headers)
    print('Response status code:', response.status_code)
    
    if response.status_code == 200:
        parking_data = response.json()
    else:
        print('Error:', response.text)  # Print the error message
        parking_data = []

    return parking_data

@app.route('/')
@protected_route
def dashboard():
    access_token = session.get('jwt_token')
    token_type = "bearer"  # You can set the token type as needed
    # Fetch the user data from the FastAPI server
    user_id=get_user_id_from_session_cookie()
    api_url = f'{API_DATA}/users/{user_id}'
    
    headers = {
        'Authorization': f'Bearer {access_token}'  # Include the JWT token in the request headers
    }

    response = requests.get(api_url, headers=headers)


    #Quantity of users
    api_users=f'{API_DATA}/users/'
    users=requests.get(api_users, headers=headers)

    if users.status_code == 200:
        cantidad_users = len(users.json())
    else:
        cantidad_users="Error"
    
    #Quantity of available parkings
    api_parkings=f'{API_ESTACIONAMIENTOS}/parking_spaces/'
    parkings=requests.get(api_parkings, headers=headers)
    parking_locations=parkings.json()
    if parkings.status_code == 200:
        filtered_parking_locations_active = [location for location in parking_locations if location['state']==True]
        filtered_parking_locations_active=len(filtered_parking_locations_active)
        filtered_parking_locations_innactive = [location for location in parking_locations if location['state']==False]
        filtered_parking_locations_innactive=len(filtered_parking_locations_innactive)
    else:
        filtered_parking_locations_active="Error"
        filtered_parking_locations_innactive="Error"

    # Obtiene resúmenes de movimientos
    api_movements = 'https://api2.parkingtalcahuano.cl/parking-movements/'
    movements = requests.get(api_movements, headers=headers)

    if movements.status_code == 200:
        movement_summary = movements.json()[:5]
    else:
        movement_summary = "Error"


    # Cálculo de totales de movimientos
    total_reserved_cost = sum(movement['total_cost'] for movement in movement_summary if 'Cancelacion' not in movement['notes'])
    total_other_cost = sum(movement['total_cost'] for movement in movement_summary if 'Cancelacion'  in movement['notes'])
    total_general = sum(movement['total_cost'] for movement in movement_summary)

    # Crear un diccionario con los totales
    totals = {
        'total_reserved_cost': total_reserved_cost,
        'total_other_cost': total_other_cost,
        'total_general': total_general
    }

    if response.status_code == 200:
        user_data = response.json()
        username = user_data.get('username')
        context_data = {
            'access_token': access_token,
            'token_type': token_type,
            'current_user': username,
            'cantidad_users': cantidad_users,
            'filtered_parking_locations_active': filtered_parking_locations_active,
            'filtered_parking_locations_innactive': filtered_parking_locations_innactive,
            'parking_space_data': parking_locations,
            'movement_summary': movement_summary,  
            'totals': totals ,
        }
        

        return render_template('index.html', **context_data)

    # Handle the case when the request to the FastAPI server fails
    print('Failed to fetch user data.', 'error')
    return render_template('index.html', access_token=access_token, token_type=token_type)


@app.route('/wallets')
def list_wallets():
    if 'jwt_token' in session:
        access_token = session['jwt_token']

        # Make an API request to get a list of wallets
        api_url = 'https://api2.parkingtalcahuano.cl/wallets'  # Update with your actual API endpoint
        headers = {'Authorization': f'Bearer {access_token}'}
        response = requests.get(api_url, headers=headers)

        if response.status_code == 200:
            wallets = response.json()
            return render_template('billeteraUsers.html', wallets=wallets)
        else:
            flash('Failed to retrieve wallet data.', 'error')
            return render_template('billeteraUsers.html', wallets=[])
    else:
        return redirect('/login')
    

@app.route('/wallet/<int:wallet_id>/')
def wallet_detail(wallet_id):
    if 'jwt_token' in session:
        access_token = session['jwt_token']

        # Make an API request to get a list of wallets
        api_url = 'https://api2.parkingtalcahuano.cl/wallets'  # Update with your actual API endpoint
        headers = {'Authorization': f'Bearer {access_token}'}
        response = requests.get(api_url, headers=headers)

        if response.status_code == 200:
            wallets = response.json()
            print(wallets)
        else:
            wallets = []

        wallet = next((w for w in wallets if w['id'] == wallet_id), None)
        if wallet is None:
        # Wallet not found, you can return an error page or a message
            return "Wallet not found", 404

    return render_template('billetera.html', wallet=wallet)




@app.route('/login', methods=['GET', 'POST'])
def login():
    form = LoginForm()
    error_message = None 

    if request.method == 'POST':
        if form.validate_on_submit():
            # Get the form data
            username = request.form['username']
            password = request.form['password']

            # Perform additional form validation (if needed)
            if not username or not password:
                error_message = 'Username and password are required.'
            else:
                # Prepare the data for the POST request
                data = {
                    'username': username,
                    'password': password
                }

                # Make the POST request to the API
                api_url = f'{API_DATA}/login-admin'
                response = requests.post(api_url, data=data, headers={'Content-Type': 'application/x-www-form-urlencoded'})

                if response.status_code == 200:
                    try:
                        # Parse the JSON response content
                        response_data = response.json()
                        access_token = response_data.get('access_token')
                        token_type = response_data.get('token_type')

                        # Set the session cookie
                        session['jwt_token'] = access_token

                        # Redirect to the dashboard
                        flash('Login successful!', 'success')
                        return redirect('/')
                    except ValueError:
                        error_message = 'Invalid JSON response from the API.'
                else:
                    error_message = 'Inicio de Sesión Fallido. Credenciales Inválidas.'

        # If form validation failed, display the error message
        if error_message:
            flash(error_message, 'error')

    # If it's a GET request or if login fails, render the login form
    return render_template('login.html', form=form, error_message=error_message)

@app.route('/logout')
def logout():
    # Remove the 'jwt_token' from the session to log the user out
    session.pop('jwt_token', None)
    
    # Redirect to the login page or any other desired page
    return redirect(('login'))

# Number of users per page
PER_PAGE = 10



@app.route('/move', methods=['GET', 'POST'])
def move():
    global rampa_arriba 
    
    if request.method == 'POST':
        direction = request.form.get('direction')
        # Lógica para cambiar el estado de la rampa
        

        if direction in ['backward', 'forward']:
            # Cambia la dirección IP y el puerto según la configuración de tu ESP32
            esp32_url = f'http://192.168.1.102/move/{direction}'

            try:
                # Envía la solicitud POST a la dirección de tu ESP32
                response = requests.post(esp32_url)
                if direction == 'forward':
                    rampa_arriba = False
                elif direction == 'backward':
                    rampa_arriba = True
                

                # Renderiza el template con la respuesta del ESP32
                return render_template('moveservo.html', response_text=response.text,rampa_arriba=rampa_arriba)
            except requests.RequestException as e:
                # Maneja cualquier error de solicitud aquí
                return render_template('moveservo.html', response_text=f"Error: {str(e)}")

    # Si la solicitud es GET o si no se especifica la dirección, simplemente renderiza la página con un mensaje predeterminado
    return render_template('moveservo.html', response_text='Presiona uno de los botones para mover el servo')

@app.route('/usuarios')
@protected_route
def user_list():
    page = request.args.get(get_page_parameter(), type=int, default=1)
    offset = (page - 1) * PER_PAGE
    
    access_token = session.get('jwt_token')
    user_id = get_user_id_from_session_cookie()
    
    user_data = fetch_user_data(access_token)
    c_user_data = fetch_current_user_data(access_token, user_id)

    # Obtener el término de búsqueda del parámetro 'search_query'
    search_query = request.args.get('search_query', '')

    # Filtrar la lista de usuarios por nombre o correo electrónico
    filtered_users = [user for user in user_data if search_query.lower() in user['username'].lower() or search_query.lower() in user['email'].lower()]

    total = len(filtered_users)

    users_on_page = filtered_users[offset:offset + PER_PAGE]

    pagination = Pagination(page=page, total=total, per_page=PER_PAGE)

    return render_template('listUsers.html', users=users_on_page, pagination=pagination, current_user=c_user_data)

def fetch_parking_space(access_token, parking_space_id):
    api_url = f'{API_ESTACIONAMIENTOS}/parking_spaces/{parking_space_id}/'
    
    headers = {
        'Authorization': f'Bearer {access_token}'  # Include the JWT token in the request headers
    }

    response = requests.get(api_url, headers=headers)

    if response.status_code == 200:
        parking_space = response.json()
    else:
        parking_space = None

    return parking_space


@app.route('/activate_user/<int:user_id>', methods=['PUT'])
@protected_route
def activate_user(user_id):
    access_token = session.get('jwt_token')
    api_url = f'https://api2.parkingtalcahuano.cl/users/{user_id}/activate'

    # Get the desired is_active status from the request data
    is_active = request.json.get('is_active', False)  # Assuming the is_active status is provided in the JSON data

    headers = {
        'Authorization': f'Bearer {access_token}',
        'Content-Type': 'application/json'
    }

    # Prepare the data for the PUT request
    data = {
        'is_active': is_active
    }

    response = requests.put(api_url, json=data, headers=headers)

    if response.status_code == 200:
        flash(f'Successfully {"activated" if is_active else "deactivated"} user {user_id}.', 'success')
    else:
        flash('Failed to activate/deactivate user.', 'error')

    return redirect(url_for('user_list'))

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

    # Obtener el término de búsqueda del parámetro 'search_query'
    search_query = request.args.get('search_query', '')

    # Filtrar la lista de espacios de estacionamiento por nombre o ubicación
    filtered_spaces = [space for space in parking_space_data if search_query.lower() in space['name'].lower() or search_query.lower() in space['location'].lower()]


    per_page = 10  # Number of items per page
    total = len(filtered_spaces)  # Total number of items
    page = request.args.get('page', type=int, default=1)  # Get the current page from the request

    pagination = Pagination(page=page, per_page=per_page, total=total, bs_version=4)

    spaces_on_page = filtered_spaces[(page - 1) * per_page: page * per_page]


    return render_template('listParking.html', parking_space_data=spaces_on_page, pagination=pagination)


from datetime import datetime, date

@app.route('/lista_reservas')
@protected_route
def reservations():
    access_token = session.get('jwt_token')
    parking_space_data = fetch_reservas_data(access_token)

    # Obtener los valores de fecha de inicio y fecha de fin para el filtro
    start_date = request.args.get('start_date')
    end_date = request.args.get('end_date')

    # Convertir las fechas de cadena a objetos date si se proporcionan
    start_date_obj = datetime.strptime(start_date, '%Y-%m-%d').date() if start_date else None
    end_date_obj = datetime.strptime(end_date, '%Y-%m-%d').date() if end_date else None

    # Filtrar la lista de reservas por las fechas proporcionadas
    filtered_reservations = parking_space_data

    if start_date_obj:
        filtered_reservations = [reservation for reservation in filtered_reservations if datetime.strptime(reservation['start_time'], '%Y-%m-%dT%H:%M:%S').date() >= start_date_obj]

    if end_date_obj:
        filtered_reservations = [reservation for reservation in filtered_reservations if datetime.strptime(reservation['end_time'], '%Y-%m-%dT%H:%M:%S').date() >= end_date_obj]

    per_page = 10  # Número de elementos por página
    total = len(filtered_reservations)  # Total de elementos
    page = request.args.get('page', type=int, default=1)  # Obtener la página actual de la solicitud

    pagination = Pagination(page=page, per_page=per_page, total=total, bs_version=4)

    reservations_on_page = filtered_reservations[(page - 1) * per_page: page * per_page]

    return render_template('listReservas.html', reservations_data=reservations_on_page, pagination=pagination)


@app.route('/agregar_estacionamiento', methods=['GET', 'POST'])
@protected_route
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


@app.route('/parking/<parking_id>')
def parking_description(parking_id):

    access_token = session.get('jwt_token')

    space = fetch_parking_space(access_token,parking_id)
    #parking_data = get_parking_data_by_id(parking_id)

    return render_template('parking.html',space=space)

@app.route('/perfil')
def profile():



    return render_template('buttons.html')


@app.route('/maps')
def map():
    access_token = session.get('jwt_token')
    parking_spaces = fetch_parking_data(access_token)
    return render_template('mapa.html', parking_spaces=parking_spaces)






@app.route('/generate_pdf_report')
def generate_pdf_report():
    # Replace this with your actual API endpoint and headers
    api_endpoint = 'https://api2.parkingtalcahuano.cl/users/'
    headers = {'accept': 'application/json'}

    # Make the API request
    response = requests.get(api_endpoint, headers=headers)
    users_data = response.json()

    # Create a PDF buffer
    pdf_buffer = io.BytesIO()

    # Use reportlab to generate the PDF report
    p = canvas.Canvas(pdf_buffer, pagesize=letter)

    # Set up styles
    styles = {
        'Title': ('Helvetica', 14),
        'Subtitle': ('Helvetica', 12),
        'Normal': ('Helvetica', 8),  # Reduced font size
    }

    # Add a title
    p.setFont(*styles['Title'])
    p.drawString(100, 750, 'Informe de Usuarios')

    # Add a subtitle
    p.setFont(*styles['Subtitle'])
    p.drawString(100, 730, 'Detalles de Usuarios')

    # Create a table header
    table_header = ['ID Usuario', 'Nombre de Usuario', 'Correo Electrónico', 'Fecha de Última Conexión', 'Fecha de Creación', 'Rol', '¿Activo?']
    col_widths = [40, 80, 80, 100, 100, 40, 40]  # Reduced column widths
    row_height = 15  # Reduced row height
    y_position = 700

    # Draw the table header
    p.setFont(*styles['Normal'])
    for col, header in enumerate(table_header):
        p.drawString(100 + sum(col_widths[:col]), y_position, header)

    # Draw the table content
    y_position -= row_height
    for user in users_data:
        for col, key in enumerate(['id', 'username', 'email', 'last_connection', 'created_date', 'role', 'is_active']):
            value = str(user[key])
            
            # Special handling for 'is_active' column
            if key == 'is_active':
                value = 'Si' if user[key] else 'No'
            p.drawString(100 + sum(col_widths[:col]), y_position, value)

        y_position -= row_height

    p.showPage()
    p.save()

    # Create a PDF response
    pdf_buffer.seek(0)
    pdf_response = Response(pdf_buffer.getvalue(), content_type='application/pdf')
    pdf_response.headers['Content-Disposition'] = 'inline; filename=informe_usuarios.pdf'

    return pdf_response


@app.route('/generate_movements_report')
def generate_movements_report():
    api_endpoint = 'https://api2.parkingtalcahuano.cl/parking-movements/'
    headers = {'accept': 'application/json'}

    # Make the API request
    response = requests.get(api_endpoint, headers=headers)
    movements_data = response.json()

    # Create a PDF buffer
    pdf_buffer = io.BytesIO()

    # Use reportlab to generate the PDF report
    p = canvas.Canvas(pdf_buffer, pagesize=letter)

    # Set up styles
    styles = {
        'Title': ('Helvetica', 14),
        'Subtitle': ('Helvetica', 12),
        'Normal': ('Helvetica', 8),  # Reduced font size
    }

    # Add a title
    p.setFont(*styles['Title'])
    p.drawString(100, 750, 'Informe de Movimientos de Estacionamiento')

    # Add a subtitle
    p.setFont(*styles['Subtitle'])
    p.drawString(100, 730, 'Detalles de Movimientos')

    # Create a table header
    table_header = ['ID Movimiento', 'ID Usuario', 'Fecha y Hora de Entrada', 'Fecha y Hora de Salida', 'ID Estacionamiento', 'Costo Total', 'Notas']
    col_widths = [40, 60, 120, 120, 80, 60, 80, 80, 120]  # Adjusted column widths
    row_height = 15  # Reduced row height
    y_position = 680  # Adjusted starting y_position

    # Draw the table header
    p.setFont(*styles['Normal'])
    for col, header in enumerate(table_header):
        p.drawString(100 + sum(col_widths[:col]), y_position, header)

    # Draw the table content
    y_position -= row_height
    for movement in movements_data:
        for col, key in enumerate(['id', 'user_id', 'entry_time', 'exit_time', 'parking_spot_id', 'total_cost', 'notes']):
            value = str(movement[key])
            
            # Special handling for 'entry_time' and 'exit_time' columns (you might need to format it appropriately)
            if key in ['entry_time', 'exit_time']:
                value = value[:19]  # Assuming the date and time format is suitable for display
            
            p.drawString(100 + sum(col_widths[:col]), y_position, value)

        y_position -= row_height

    p.showPage()
    p.save()

    # Create a PDF response
    pdf_buffer.seek(0)
    pdf_response = Response(pdf_buffer.getvalue(), content_type='application/pdf')
    pdf_response.headers['Content-Disposition'] = 'inline; filename=informe_movimientos.pdf'

    return pdf_response

@app.route('/reportes')
def report():
    
    return render_template('informes.html')



@app.route('/edit_user/<int:user_id>', methods=['GET', 'POST'])
def edit_user(user_id):

    user_id=get_user_id_from_session_cookie()
    api_url = f'{API_DATA}/users/{user_id}'
    
    headers = {
        'Authorization': f'Bearer {access_token}'  # Include the JWT token in the request headers
    }

    response = requests.get(api_url, headers=headers)

    # Retrieve the user from your API or database based on the user_id
    user = get_user_by_id(user_id)  # Implement 'get_user_by_id' to fetch the user

    if request.method == 'POST':
        # Update user information based on the form data
        user.username = request.form.get('username')
        user.email = request.form.get('email')
        # Update other user information as needed

        # Save the updated user to the database

        # Redirect to the user list page or a success page
        return redirect(url_for('user_list'))

    return render_template('edit_user.html', user=user)

@app.route('/edit_email/<int:user_id>', methods=['GET', 'PUT'])
def edit_email(user_id):
    access_token = session.get('jwt_token')
    users = fetch_user_data(access_token)

    if request.method == 'PUT':
        # Update the user's email based on the form submission
        new_email = request.form.get('new_email')
        
        # Find the user by ID and update the email
        user_to_update = next((user for user in users if user['id'] == user_id), None)
        
        if user_to_update:
            user_to_update['email'] = new_email
            flash(f'Successfully updated email for user {user_id}.', 'success')
            return redirect(url_for('user_list'))
        else:
            flash('User not found.', 'error')

    # If it's a GET request or the form submission failed, render the edit page
    user = next((user for user in users if user['id'] == user_id), None)
    if user:
        return render_template('edit_email.html', user=user)
    else:
        flash('User not found.', 'error')
        return redirect(url_for('user_list'))
    
    
if __name__ == '__main__':
    app.run(debug=True)
