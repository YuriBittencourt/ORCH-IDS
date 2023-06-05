import os
from pymongo import MongoClient

from flask import Flask, render_template, request, redirect, session, url_for
from dotenv import load_dotenv

app = Flask(__name__)
app.secret_key = 'sua_chave_secreta'  # Defina sua própria chave secreta
load_dotenv()
credentials = {"username": os.getenv("ADMIN_USER"), "password": os.getenv("ADMIN_PASSWORD")}

mongo_host = os.getenv('MONGO_HOST')
mongo_port = int(os.getenv('MONGO_PORT'))
mongo_db = os.getenv('MONGO_DB')
client = MongoClient(host=mongo_host, port=mongo_port)
db = client[mongo_db]

collections = {
    'packets': os.getenv('MONGO_COLLECTION_QUEUE'),
    'rules': os.getenv('MONGO_COLLECTION_RULES'),
    'blacklist': os.getenv('MONGO_COLLECTION_BLACKLISTED'),
    'alerts': os.getenv('MONGO_COLLECTION_ALERTS')
}


@app.route('/')
def dashboard():
    if 'username' in session:
        username = session['username']
        return render_template('dashboard.html', username=username)
    else:
        return redirect(url_for('login'))

@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']

        if username == credentials["username"] and password == credentials["password"]:
            session['username'] = username
            return redirect(url_for('dashboard'))
        else:
            return render_template('login.html', error='Invalid Credentials!')

    return render_template('login.html')


@app.route('/logout')
def logout():
    session.pop('username', None)
    return redirect(url_for('login'))


@app.route('/regras', methods=['GET', 'POST', 'UPDATE'])
def regras():
    if request.method == 'GET':
        return render_template('regras.html', regras=db[collections['rules']].find())


@app.route('/pacotes')
def pacotes():
    return render_template('pacotes.html')


@app.route('/alertas')
def alertas():
    return render_template('alertas.html')


if __name__ == '__main__':
    app.run(host='0.0.0.0', debug=True)
