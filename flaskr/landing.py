import functools
from flask import (Blueprint, flash, g, redirect, render_template, request, session, url_for,current_app)
from werkzeug.security import check_password_hash, generate_password_hash
from flaskr.db import get_db
from flask_mail import Mail
from itsdangerous import URLSafeTimedSerializer, SignatureExpired
import hashlib
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
            if not user['confirm_login']:
                error = 'Link to verify your email has been sent. Please verify your email to login.'
                token = hashlib.sha256((str(user['id']) + '\x19^|\x8aK\xa7\xe5\xb8\xc3\xb7z2u45W').encode('utf-8')).hexdigest()
                db.execute('UPDATE user SET confirm_login_token = ? WHERE id = ?', (token, user['id']))
                db.commit()
                verify_url = url_for('landing.verify', token=token, _external=True)
                mail = Mail(current_app)
                mail.send_message(
                    subject='Please Verify Your Email',
                    recipients=[email],
                    html=f'<p>Please click the link below to verify your email:</p><p><a href="{verify_url}">Verify Email</a></p>'
                )
                flash('Please verify your email before logging in. A link has been sent to your email.')
                return render_template('landing/login.html')
            else:
                return redirect(url_for('index'))

        flash(error)

    return render_template('landing/login.html')

@bp.route('/verify')
def verify():
    token = request.args.get('token')
    db = get_db()
    user = db.execute('SELECT * FROM user WHERE confirm_login_token = ?', (token,)).fetchone()

    if user is None:
        flash('Invalid verification link.')
        return redirect(url_for('index'))

    # Update the user's confirmation status
    db.execute('UPDATE user SET confirm_login = 1 WHERE id = ?', (user['id'],))
    db.commit()

    flash('Email verified successfully. You can now log in.')
    return redirect(url_for('landing.login'))

@bp.before_app_request
def load_logged_in_user():
    user_id = session.get('user_id')

    if user_id is None:
        g.user = None
    else:
        g.user = get_db().execute(
            'SELECT * FROM user WHERE id = ?', (user_id,)
        ).fetchone()

def check_email_exists(email):
    
    db = get_db()
    result = db.execute("SELECT * FROM user WHERE email = ?", (email,))
    user = result.fetchone()  # Fetch the first row
    return user is not None  # Check if a user row was found

@bp.route('/reset_password', methods=('POST',))
def reset_password():
    email = request.form['email']
    token = URLSafeTimedSerializer(current_app.config['SECRET_KEY']).dumps(email, salt='reset-salt')
    link = url_for('landing.reset_with_token', token=token, _external=True)
    if check_email_exists(email):
        # Send reset link logic here
        # ... (implementation to send reset link)
        mail = Mail(current_app)
        mail.send_message(
            subject='Password Reset',
            recipients=[email],
            body=f'Click the link to reset your password: {link}'
        )
        flash('A password reset link has been sent to your email.')
        return redirect(url_for('landing.login'))
    else:
        flash('Email not found. Please try again.')
        return redirect(url_for('landing.login'))
    
@bp.route('/reset_password/<token>', methods=['GET', 'POST'])
def reset_with_token(token):
    try:
        email = URLSafeTimedSerializer(current_app.config['SECRET_KEY']).loads(token, salt='password-reset-salt', max_age=3600)
    except SignatureExpired:
        flash('The reset link is invalid or has expired.', 'danger')
        return redirect(url_for('landing.reset_password'))

    if request.method == 'POST':
        new_password = request.form['password']
        confirm_password = request.form['confirm_password']

        if new_password != confirm_password:
            flash('Passwords do not match. Please try again.')
            return redirect(url_for('landing.reset_with_token', token=token))
        
        hashed_password = generate_password_hash(new_password)
        # Update user's password in the database
        db = get_db()
        db.execute(
            'UPDATE user SET password = ? WHERE email = ?',
            (hashed_password, email)
        )
        db.commit()

        flash('Your password has been updated.')
        return redirect(url_for('landing.login'))

    return render_template('reset_with_token.html', token=token)

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