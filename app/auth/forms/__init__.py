from flask_wtf import FlaskForm
from wtforms import validators
from wtforms.fields import *
from wtforms.validators import *


class login_form(FlaskForm):
    email = EmailField('Email Address', [
        validators.DataRequired(),
    ])

    password = PasswordField('Password', [
        validators.DataRequired(),
        validators.length(min=6, max=35)
    ])
    submit = SubmitField()


class register_form(FlaskForm):

    email = EmailField('Email Address', [
        validators.DataRequired()

    ], description="You need to signup with an email")

    password = PasswordField('Create Password', [
        validators.DataRequired(),
        validators.EqualTo('confirm', message='Passwords must match'),
        validators.length(min=6, max=35)

    ], description="Create a password ")
    confirm = PasswordField('Repeat Password', description="Please retype your password to confirm it is correct")
    submit = SubmitField()

    def validate_password(self, password):
        errors = []
        lower_case_chars = "abcdefghijklmnopqrstuvwxyz"
        has_lower_case = False
        for char in self.password.data:
            if char in lower_case_chars:
                has_lower_case = True
        if has_lower_case == False:
            errors.append('a lower case letter')

        upper_case_chars = "ABCDEFGHIJKLMNOPQRSTUVWXYZ"
        has_upper_case = False
        for char in self.password.data:
            if char in upper_case_chars:
                has_upper_case = True
        if has_upper_case == False:
            errors.append(' an upper case letter')

        special_chars = "!@#$%^&*()+={}[]'/<>\\"
        has_special_chars = False
        for char in self.password.data:
            if char in special_chars:
                has_special_chars = True
        if has_special_chars == False:
            errors.append(' a special character')

        if len(errors) != 0:
            error_string = f"Your password is missing the following characteristics: "
            for e in errors:
                error_string = error_string + e
            raise ValidationError(error_string)


class profile_form(FlaskForm):
    about = TextAreaField('About', [validators.length(min=6, max=300)],
                          description="Please add information about yourself")

    submit = SubmitField()

class user_edit_form(FlaskForm):
    about = TextAreaField('About', [validators.length(min=6, max=300)],
                          description="Please add information about yourself")
    is_admin = BooleanField('Admin', render_kw={'value':'1'})
    submit = SubmitField()


class security_form(FlaskForm):
    email = EmailField('Email Address', [
        validators.DataRequired(),

    ], description="You can change your email address")

    password = PasswordField('Create Password', [
        validators.DataRequired(),
        validators.EqualTo('confirm', message='Passwords must match'),

    ], description="Create a password ")
    confirm = PasswordField('Repeat Password', description="Please retype your password to confirm it is correct")

    submit = SubmitField()

class csv_upload(FlaskForm):
    file = FileField()
    submit = SubmitField()
