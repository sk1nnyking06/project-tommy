import functools

from flask import (
    Blueprint, flash, g, redirect, render_template, request, session, url_for
)
from werkzeug.security import check_password_hash, generate_password_hash

from flaskr.db import get_db

bp = Blueprint('landing', __name__)

@bp.route('/home')
def home():
    return render_template('landing/home.html')

@bp.route('/about')
def about():
    return render_template('landing/about.html')

@bp.route('/pricing')
def pricing():
    return render_template('landing/pricing.html')

@bp.route('/privacy')
def privacy():
    return render_template('landing/privacy.html')

@bp.route('/terms')
def terms():
    return render_template('landing/terms.html')

@bp.route('/register', methods = ('GET', 'POST'))
def register():
    if request.method == 'POST':
        email = request.form['email'].strip()
        password = request.form['password'].strip()
        first_name = request.form['first_name'].strip()
        last_name = request.form['last_name'].strip()
        reenter_password = request.form['reenter_password'].strip()
        phone = request.form['phone'].strip()
        company_name = request.form['company_name'].strip()
        company_city = request.form['company_city'].strip()
        country = request.form['country'].strip()
        state = request.form['state'].strip()
        db = get_db()
        error = None

        if not email:
            error = 'Email is required.'
        elif password != reenter_password:
            error = 'Passwords do not match.'
        elif not password:
            error = 'Password is required.'
        elif not first_name:
            error = 'First Name is required.'
        elif not last_name:
            error = 'Last Name is required.'
        elif not reenter_password:
            error = 'Please confirm password.'
        elif not phone:
            error = 'Phone is required.'
        elif not company_name:
            error = 'Company Name is required.'
        elif not company_city:
            error = 'Company City is required.'
        elif not country:
            error = 'Country is required.'
        elif not state:
            error = 'State is required.'

        if error is None:
            try:
                db.execute(
                    "INSERT INTO user (email, password, first_name, last_name, phone, company_name, company_city, company_country, company_state) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)",
                    (email, generate_password_hash(password), first_name, last_name, phone, company_name, company_city, country, state),
                )
                db.commit()
            except db.IntegrityError:
                error = f"User {email} is already registered."
            else:
                return redirect(url_for("landing.login"))

        flash(error)

    return render_template('landing/register.html')

@bp.route('/login', methods=('GET', 'POST'))
def login():
    if request.method == 'POST':
        email = request.form['email']
        password = request.form['password']
        db = get_db()
        error = None
        user = db.execute(
            'SELECT * FROM user WHERE email = ?', (email,)
        ).fetchone()

        if user is None:
            error = 'Incorrect email.'
        elif not check_password_hash(user['password'], password):
            error = 'Incorrect password.'

        if error is None:
            session.clear()
            session['user_id'] = user['id']
            return redirect(url_for('index'))

        flash(error)

    return render_template('landing/login.html')

@bp.before_app_request
def load_logged_in_user():
    user_id = session.get('user_id')

    if user_id is None:
        g.user = None
    else:
        g.user = get_db().execute(
            'SELECT * FROM user WHERE id = ?', (user_id,)
        ).fetchone()

@bp.route('/logout')
def logout():
    session.clear()
    return redirect(url_for('index'))

def login_required(view):
    @functools.wraps(view)
    def wrapped_view(**kwargs):
        if g.user is None:
            return redirect(url_for('landing.login'))

        return view(**kwargs)

    return wrapped_view