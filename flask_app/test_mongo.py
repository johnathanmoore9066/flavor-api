from flask import Flask
from flask_pymongo import PyMongo
import os

app = Flask(__name__)
app.config['MONGO_URI'] = "mongodb+srv://johnathanmoore9067:DDys44ia11@chefai.aqoz7.mongodb.net/chefai?retryWrites=true&w=majority&appName=ChefAI"
mongo = PyMongo(app)

try:
    collections = mongo.db.list_collection_names()
    print("MongoDB connection successful!")
    print("Available collections:", collections)
except Exception as e:
    print(f"MongoDB error: {e}")
