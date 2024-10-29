import os

from flask import Flask

def create_app(test_config=None):
    # create and configure the app
    app = Flask(__name__, instance_relative_config=True)
    app.config.from_mapping(
        SECRET_KEY='d7e955624918fe25e63d6cd31fcbe3b2973155364565b853ed5446223071a96e',
        DATABASE=os.path.join(app.instance_path, 'flaskr.sqlite'),
        MAIL_SERVER='live.smtp.mailtrap.io',
        MAIL_PORT=587,
        MAIL_USERNAME= 'api',
        MAIL_PASSWORD= '94b002fe73f9f151ce40321cc713c090',
        MAIL_USE_TLS= True,
        MAIL_USE_SSL= False,
        MAIL_DEFAULT_SENDER= 'api@demomailtrap.com',
    )

    if test_config is None:
        # load the instance config, if it exists, when not testing
        app.config.from_pyfile('config.py', silent=True)
    else:
        # load the test config if passed in
        app.config.from_mapping(test_config)

    # ensure the instance folder exists
    try:
        os.makedirs(app.instance_path)
    except OSError:
        pass
    
    from . import db
    db.init_app(app)

    from . import landing
    app.register_blueprint(landing.bp)

    return app