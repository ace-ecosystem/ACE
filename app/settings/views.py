from app.settings import settings as app
from flask import render_template, request, make_response
from flask_login import login_required, current_user
import json
import logging
import saq
import saq.audit
from saq.error import report_exception
import saq.settings
from sqlalchemy.exc import IntegrityError
import urllib.parse

@app.route('/', methods=['GET', 'PUT', 'DELETE'])
@login_required
def manage():
    # get parameters
    body = request.get_json()

    # add/update a setting
    if request.method == 'PUT':
        try:
            # if adding new setting
            if body['id'] is None:
                # create new child setting
                setting = saq.settings.new_child(body['parent_id'], body['key'], body['value'], body['children'])
                saq.audit.log(f'{current_user.display_name} - Added setting - {setting.path} - {setting.to_json()}')
            else:
                # update existing setitng
                setting = saq.settings.update(body['id'], body['key'], body['value'], body['children'])
                saq.audit.log(f'{current_user.display_name} - Updated setting - {setting.path} - {setting.to_json()}')

        # alert user if key alreayd exists
        except IntegrityError:
            return f"{body['key']} already exists", 400

        # alert user if something broke
        except Exception as e:
            logging.error(f'failed to add/update setting: {e}')
            report_exception()
            return f'Internal Server Error: {e}', 500

    # delete a setting
    if request.method == 'DELETE':
        try:
            setting = saq.settings.delete(body['id'])
            saq.audit.log(f'{current_user.display_name} - Deleted setting - {setting.path} - {setting.to_json()}')

        except Exception as e:
            logging.error(f'failed to delete setting: {e}')
            report_exception()
            return f"failed to delete", 500

    # render settings tree
    saq.settings.load()
    return render_template(
        'settings/manage.html',
        root_setting=saq.settings.root,
        import_enabled=saq.CONFIG['gui'].getboolean('settings_import_enabled'),
    )

@app.route('/add', methods=['POST'])
@login_required
def add():
    body = request.get_json()
    return render_template('settings/edit.html', setting=saq.settings.get(body['id']).new_child())

@app.route('/edit', methods=['POST'])
@login_required
def edit():
    body = request.get_json()
    return render_template('settings/edit.html', setting=saq.settings.get(body['id']))

@app.route('/export', methods=['GET'])
@login_required
def export():
    saq.settings.load()
    root = saq.settings.root.to_json(indent=4, sort_keys=True)
    response = make_response(root.encode('utf-8'))
    response.headers['Content-Type'] = 'application/json';
    response.headers['Content-Disposition'] = 'attachment; filename="settings.json"'
    return response

@app.route('/import', methods=['PUT'])
@login_required
def import_settings():
    body = request.get_json()
    saq.settings.import_settings(body)
    return ('', 204)
