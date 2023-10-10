from flask_wtf import FlaskForm
from wtforms import StringField, FloatField, BooleanField, PasswordField, SubmitField

from wtforms.validators import DataRequired

class ParkingSpaceForm(FlaskForm):
    name = StringField('Nombre', validators=[DataRequired()])
    description = StringField('Descripcion', validators=[DataRequired()])
    location = StringField('Locación', validators=[DataRequired()])
    latitude = FloatField('Latitud', validators=[DataRequired()])
    longitude = FloatField('Longitud', validators=[DataRequired()])
    state = BooleanField('Estado (Disponible)')

class LoginForm(FlaskForm):
    username = StringField('Usuario', validators=[DataRequired()])
    password = PasswordField('Contraseña', validators=[DataRequired()])
    submit = SubmitField('Ingresar')