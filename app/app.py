from flask import Flask, render_template, request, redirect, session, url_for
from dotenv import dotenv_values
from bson import ObjectId

from utils.mongo import mongo_instance as mongo
from utils.auth_decorator import authenticated_resource
from utils.setup_db import setup_db
import utils.populate_db as pop
from utils.schema import schemas

app = Flask(__name__)
config = dotenv_values()
app.secret_key = config['SECRET_KEY']
name = 'ORCH-IDS'

credentials = {'username': config['ADMIN_USER'], 'password': config['ADMIN_PASSWORD']}


@app.route('/')
@authenticated_resource
def home():
    return render_template('home.jinja2', title=name)


@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']

        if username == credentials['username'] and password == credentials['password']:
            session['username'] = username
            return redirect(url_for('home'))
        else:
            return render_template('login.jinja2', error='Invalid Credentials!')

    return render_template('login.jinja2', title=name)


@app.route('/logout')
@authenticated_resource
def logout():
    session.pop('username', None)
    return redirect(url_for('login'))


@app.route('/rules', methods=['GET', 'POST', 'DELETE'])
@authenticated_resource
def rules():
    # Add new rules
    if request.method == 'POST':
        try:
            new = {k: v if schemas['rules']['properties'][k]['type'] == 'string'
            else int(v) if schemas['rules']['properties'][k]['type'] == 'number'
            else bool(v) for k, v in request.form.items() if v}

            if 'direction' not in new:
                new['direction'] = False

            mongo.db[mongo.collections['rules']].insert_one(new)

        except Exception as e:
            print(e)

    # Delete rule
    if request.method == 'DELETE':
        try:
            mongo.db[mongo.collections['rules']].delete_one({'_id': ObjectId(request.json['_id'])})
        except Exception as e:
            print(e)

    # Retrieve rules
    rules_list = list(mongo.db[mongo.collections['rules']].find())
    keys = list(schemas['rules']['properties'].keys())

    return render_template('rules.jinja2', list=rules_list, keys=keys, title=name, route='/rules')


@app.route('/blacklist', methods=['GET', 'POST', 'DELETE'])
@authenticated_resource
def blacklist():
    # Blacklist new IP
    if request.method == 'POST':
        try:
            new = {k: v if schemas['blacklist']['properties'][k]['type'] == 'string'
            else int(v) if schemas['blacklist']['properties'][k]['type'] == 'number'
            else bool(v) for k, v in request.form.items() if v}

            mongo.db[mongo.collections['blacklist']].insert_one(new)

        except Exception as e:
            print(e)

    # Remove IP from blacklist
    if request.method == 'DELETE':
        try:
            mongo.db[mongo.collections['blacklist']].delete_one({'_id': ObjectId(request.json['_id'])})
        except Exception as e:
            print(e)

    # Retrieve blacklisted IPs
    ban_list = list(mongo.db[mongo.collections['blacklist']].find())
    keys = list(schemas['blacklist']['properties'].keys())

    return render_template('blacklist.jinja2', list=ban_list, keys=keys, title=name, route='/blacklist')


@app.route('/alerts', methods=['GET', 'DELETE'])
@authenticated_resource
def alerts():
    # Delete alerts
    if request.method == 'DELETE':
        try:
            mongo.db[mongo.collections['alerts']].delete_one({'_id': ObjectId(request.json['_id'])})
        except Exception as e:
            print(e)

    # Retrieve alerts
    alerts_list = list(mongo.db[mongo.collections['alerts']].aggregate([
        {
            '$addFields': {
                'timestamp': {
                    '$toDate': '$timestamp'
                }
            }
        }, {
            '$sort': {
                'timestamp': -1,
                'severity': -1
            }
        }
    ]))
    keys = list(schemas['alerts']['properties'].keys())

    return render_template('alerts.jinja2', list=alerts_list, keys=keys, title=name, route='/alerts')


@app.route('/configurations/')
@app.route('/configurations/<action>')
@authenticated_resource
def configurations(action=None):
    execute = None
    if action == 'setup_db':
        execute = setup_db

    elif action == 'drop_rules':
        execute = pop.drop_rules

    elif action == 'populate_rules':
        execute = pop.populate_rules

    elif action == 'drop_blacklist':
        execute = pop.drop_blacklist

    elif action == 'populate_blacklist':
        execute = pop.populate_blacklist

    elif action == 'drop_packets':
        execute = pop.drop_packets

    elif action == 'populate_packets':
        execute = pop.populate_packets

    elif action == 'drop_alerts':
        execute = pop.drop_alerts

    elif action == 'populate_alerts':
        execute = pop.populate_alerts

    elif action == 'drop_occurrences':
        execute = pop.drop_occurrences

    elif action == 'populate_occurrences':
        execute = pop.populate_occurrences

    if execute:
        try:
            execute()
        except Exception as e:
            print(e)

    return render_template('configurations.jinja2', title=name)


if __name__ == '__main__':
    if config['ENVIRONMENT'] == 'DEV':
        app.run(host='0.0.0.0', port=config['PORT'], debug=True)

    elif config['ENVIRONMENT'] == 'PROD':
        from waitress import serve

        serve(app, host='0.0.0.0', port=config['PORT'])

    else:
        raise ValueError('WRONG environment variable')
