from flask_pymongo import PyMongo

mongo = PyMongo()
db = None

def init_extensions(app):
    global db
    mongo.init_app(app)
    db = mongo.db  # assign after init
