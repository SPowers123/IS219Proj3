from flask_wtf import FlaskForm
from wtforms import validators
from wtforms.fields import *
from wtforms.validators import *

class csv_upload(FlaskForm):
    file = FileField()
    submit = SubmitField()

class addLocation(FlaskForm):
    title = StringField('Title', [validators.DataRequired()], description="Name of Location")
    longitude = StringField('Longitude', [validators.DataRequired()], description="Longitude coordinate")
    latitude = StringField('Latitude', [validators.DataRequired()], description="Latitude coordinate")
    population = StringField('Population', [validators.DataRequired()], description="Total population")
    submit = SubmitField()