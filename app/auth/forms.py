from flask_wtf import Form
from wtforms import StringField, PasswordField, BooleanField, SubmitField
from wtforms.validators import InputRequired, Required, Length, EqualTo, Regexp

# These are also imported in the auth.change_password view and passed through to javascript
# If you want to change complexity requirements or length requirements, do it here.
PASS_SPECIAL_CHARS = r',!@#$%^& _.'
PASS_MIN_LENGTH = 8


class LoginForm(Form):
    username = StringField('Username', validators=[Required(), Length(1, 64)])
    password = PasswordField('Password', validators=[Required()])
    remember_me = BooleanField('Keep me logged in')
    submit = SubmitField('Log In')


class ChangePasswordForm(Form):
    """Regex are broken out into separate expressions to allow for more granular error messages, which
    should be more informative to the user."""
    current_password = PasswordField('Current Password', validators=[InputRequired()])
    new_password = PasswordField('New Password', validators=[
        InputRequired(),
        EqualTo('confirm', message='Passwords must match'),
        Regexp(r'(?=.*[a-z].*$)', message='Password does not meet complexity requirements: missing lower case letter.'),
        Regexp(r'(?=.*[A-Z].*$)', message='Password does not meet complexity requirements: missing upper case letter.'),
        Regexp(r'(?=.*[0-9].*$)', message='Password does not meet complexity requirements: missing number.'),
        Regexp(f'(?=.*[{PASS_SPECIAL_CHARS}].*$)', message=f'Password does not meet complexity requirements: missing '
                                                           f'special character from {PASS_SPECIAL_CHARS} or space'),
        Length(
            min=PASS_MIN_LENGTH,
            max=-1,
            message=f'Password does not meet complexity requirements: must be {PASS_MIN_LENGTH} '
                    f'or more characters long',
        ),
    ])
    confirm = PasswordField('Confirm Password', validators=[InputRequired()])
    submit = SubmitField('Change Password')
