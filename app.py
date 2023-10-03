from flask import Flask, render_template
from flask_cors import CORS

app = Flask(__name__)
CORS(app)  # Habilita CORS para permitir solicitudes desde el navegador

@app.route('/')
def dashboard():

    return render_template('index.html')

@app.route('/login')
def login():

    return render_template('login.html')

if __name__ == '__main__':
    app.run(debug=True)
