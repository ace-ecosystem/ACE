from flask import Blueprint

events = Blueprint('events', __name__, url_prefix='/events')

from . import views
