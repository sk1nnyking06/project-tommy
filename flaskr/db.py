import sqlite3
import click
from flask import current_app, g

#this function is used to close the database connection
#when the application context is destroyed
#then it also adds the init_db_command to the cli
def init_app(app):
    app.teardown_appcontext(close_db)
    app.cli.add_command(init_db_command)

#this funtion is used to initialize the database
#it reads the schema.sql file and executes it
def init_db():
    db = get_db()

    with current_app.open_resource('schema.sql') as f:
        db.executescript(f.read().decode('utf8'))

#this defines the command line command init-db
#this command calls the init_db function and basically an easier way to initialize the database
@click.command('init-db')
def init_db_command():
    """Clear the existing data and create new tables."""
    init_db()
    click.echo('Initialized the database.')

#this function is used to get the database connection
#it creates a connection to the database if it doesn't exist
#and uses the app configuration to get the database path
def get_db():
    if 'db' not in g:
        g.db = sqlite3.connect(
            current_app.config['DATABASE'],
            detect_types=sqlite3.PARSE_DECLTYPES
        )
        g.db.row_factory = sqlite3.Row

    return g.db

#this function is used to close the database connection
def close_db(e=None):
    db = g.pop('db', None)

    if db is not None:
        db.close()