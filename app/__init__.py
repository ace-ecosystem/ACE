# vim: sw=4:ts=4:et

import base64
import logging
import time
import urllib.parse
import json

import saq

from hexdump import hexdump

from flask import Flask, render_template
from flask_bootstrap import Bootstrap
#from flask.ext.moment import Moment
from flask_login import LoginManager
from flask_sqlalchemy import SQLAlchemy
from config import config

import sqlalchemy.pool

from sqlalchemy import event
from sqlalchemy.engine import Engine

@event.listens_for(Engine, "before_cursor_execute")
def before_cursor_execute(conn, cursor, statement, parameters, context, executemany):
    if saq.CONFIG['global'].getboolean('log_sql_exec_times'):
        context._query_start_time = time.time()
        logging.debug("START QUERY {} ({})".format(statement, parameters))
    # Modification for StackOverflow answer:
    # Show parameters, which might be too verbose, depending on usage..
    #logging.debug("Parameters:\n%r" % (parameters,))

@event.listens_for(Engine, "after_cursor_execute")
def after_cursor_execute(conn, cursor, statement, parameters, context, executemany):
    if saq.CONFIG['global'].getboolean('log_sql_exec_times'):
        total = time.time() - context._query_start_time
        logging.debug("END QUERY {:02f} {} ({})".format(total * 1000, statement, parameters))

    # Modification for StackOverflow: times in milliseconds
    #logger.debug("Total Time: %.02fms" % (total*1000))

bootstrap = Bootstrap()
#moment = Moment()
login_manager = LoginManager()
login_manager.session_protection = 'strong'
login_manager.login_view = 'auth.login'

class CustomSQLAlchemy(SQLAlchemy):
    def apply_driver_hacks(self, app, info, options):
        # add SSL (if configured)
        options.update(config[saq.CONFIG['global']['instance_type']].SQLALCHEMY_DATABASE_OPTIONS)
        SQLAlchemy.apply_driver_hacks(self, app, info, options)

db = CustomSQLAlchemy()

def create_app():
    app = Flask(__name__)
    app.config.from_object(config[saq.CONFIG['global']['instance_type']])
    config[saq.CONFIG['global']['instance_type']].init_app(app)

    bootstrap.init_app(app)
    #moment.init_app(app)
    login_manager.init_app(app)
    db.init_app(app)
    
    from .main import main as main_blueprint
    app.register_blueprint(main_blueprint)

    from .auth import auth as auth_blueprint
    app.register_blueprint(auth_blueprint)

    from .analysis import analysis as analysis_blueprint
    app.register_blueprint(analysis_blueprint)

    from .events import events as events_blueprint
    app.register_blueprint(events_blueprint)

    from .settings import settings as settings_blueprint
    app.register_blueprint(settings_blueprint)
    
    #from .cloudphish import cloudphish as cloudphish_blueprint
    #app.register_blueprint(cloudphish_blueprint)

    from .vt_hash_cache import vt_hash_cache_bp as vt_hash_cache_blueprint
    app.register_blueprint(vt_hash_cache_blueprint)

    # utility functions to encoding/decoding base64 to/from strings
    def s64decode(s):
        return base64.b64decode(s + '===').decode('utf8', errors='replace')

    def s64encode(s):
        return base64.b64encode(s.encode('utf8', errors='replace')).decode('ascii')

    def b64escape(s):
        return base64.b64encode(urllib.parse.quote(s.encode('utf8', errors='replace')).encode('ascii')).decode('ascii')

    def b64decode_wrapper(s):
        # sometimes base64 encoded data that tools send do not have the correct padding
        # this deals with that without breaking anything
        return base64.b64decode(s + '===')

    def btoa(b):
        return b.decode('ascii')

    def json_str_to_dict(s):
        return json.loads(s)

    def custom_error_missing_question(value):
        try:
            return value.question
        except:
            return "ERROR: Edge case conundrums with caching and archiving cleanup."

    def dict_to_indented_json(d):
        return json.dumps(d, indent=2, default=str)

    app.jinja_env.filters['btoa'] = btoa
    app.jinja_env.filters['b64decode'] = b64decode_wrapper
    app.jinja_env.filters['b64encode'] = base64.b64encode
    app.jinja_env.filters['s64decode'] = s64decode
    app.jinja_env.filters['s64encode'] = s64encode
    app.jinja_env.filters['b64escape'] = b64escape
    app.jinja_env.filters['hexdump'] = hexdump
    app.jinja_env.filters['json_str_to_dict'] = json_str_to_dict
    app.jinja_env.filters['dict_to_indented_json'] = dict_to_indented_json
    app.jinja_env.filters['custom_error_missing_question'] = custom_error_missing_question

    # add the "do" template command
    app.jinja_env.add_extension('jinja2.ext.do')

    return app
