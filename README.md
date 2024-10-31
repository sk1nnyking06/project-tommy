# project-tommy

To run app you need to first set up a Flask virtual environment:
1) pip install virtualenv
2) python -m venv venv
3) close out and reopen terminal and I think that works?

To initialize the database:
1) flask --app flaskr init-db

To actual start the app: 
1) flask --app flaskr run --debug

For email testing purposes we only have it set up to work with this email, laidaniel06@gmail.com, we would need to upgrade the API to support other emails.
