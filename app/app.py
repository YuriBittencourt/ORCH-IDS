from utils.mongo import Mongo
from utils.auth_decorator import authenticated_resource
from flask import Flask, render_template, request, redirect, session, url_for
from dotenv import dotenv_values

app = Flask(__name__)
config = dotenv_values()
app.secret_key = config['SECRET_KEY']
name = "NIDS"

credentials = {"username": config["ADMIN_USER"], "password": config["ADMIN_PASSWORD"]}

mongo = Mongo()

collections = {
    'packets': config['MONGO_COLLECTION_QUEUE'],
    'rules': config['MONGO_COLLECTION_RULES'],
    'blacklist': config['MONGO_COLLECTION_BLACKLISTED'],
    'alerts': config['MONGO_COLLECTION_ALERTS']
}

@app.route('/')
@authenticated_resource
def home():
    username = session['username']
    return render_template('dashboard.html', username=username, title=name)


@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']

        if username == credentials["username"] and password == credentials["password"]:
            session['username'] = username
            return redirect(url_for('home'))
        else:
            return render_template('login.html', error='Invalid Credentials!')

    return render_template('login.html', title=name)


@app.route('/logout')
@authenticated_resource
def logout():
    session.pop('username', None)
    return redirect(url_for('login'))


@app.route('/rules', methods=['GET', 'POST', 'UPDATE'])
@authenticated_resource
def rules():
    if request.method == 'GET':
        return render_template('regras.html', regras=list(mongo.db[mongo.collections['rules']].find()), title=name)


@app.route('/blacklist', methods=['GET', 'POST', 'DELETE'])
@authenticated_resource
def blacklist():
    if request.method == 'POST':
        try:
            new = {"ip": request.form['ip'], "version": int(request.form['version']), 'reason': request.form['reason']}
            mongo.db[mongo.collections['blacklist']].insert_one(new)
        except Exception as e:
            print(e)

    if request.method == 'DELETE':
        try:
            print({"_id": request.json["ip"]})
            mongo.db[mongo.collections['blacklist']].delete_one({"ip": request.json["ip"]})
        except Exception as e:
            print(e)

    ban_list = list(mongo.db[mongo.collections['blacklist']].find())
    keys = []
    if ban_list:
        keys = list(ban_list[0].keys())
        keys.remove('_id')

    return render_template('blacklist.html', blacklist=ban_list, keys=keys, title=name)


@app.route('/alerts')
@authenticated_resource
def alerts():
    return render_template('alertas.html', title=name)


@app.route('/configurations')
@authenticated_resource
def configurations():
    return render_template('config.html', title=name)


if __name__ == '__main__':
    if config['ENVIRONMENT'] == 'DEV':
        app.run(host="0.0.0.0", port=config['PORT'], debug=True)

    elif config['ENVIRONMENT'] == 'PROD':
        from waitress import serve
        serve(app, host="0.0.0.0", port=config['PORT'])

    else:
        raise ValueError('WRONG environment variable')

