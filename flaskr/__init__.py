import os

from flask import Flask

#this function creates the app
def create_app(test_config=None):
    app = Flask(__name__, instance_relative_config=True)
    #these are the configurations for the app
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
    #this is used just incase a config.py file is present in the instance folder
    #but we are not using one but we'll just leave it if we need it in the future
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
    
    #this imports the database into the app
    from . import db
    db.init_app(app)

    #this imports the landing blueprint into the app
    from . import landing
    app.register_blueprint(landing.bp)

    return app