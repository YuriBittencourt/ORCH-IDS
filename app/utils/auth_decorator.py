from functools import wraps
from flask import session, redirect, url_for


def authenticated_resource(f):
    @wraps(f)
    def decorated(*args, **kwargs):
        if 'username' in session:
            return f(*args, **kwargs)

        return redirect(url_for('login'))

    return decorated