import os
from flask import Flask
from werkzeug.middleware.shared_data import SharedDataMiddleware
from urls import *
from models import db

def configure_uploads(app):
    # Create uploads directory if it doesn't exist
    upload_dir = 'uploads/mess_images'
    os.makedirs(upload_dir, exist_ok=True)
    
    # Serve uploaded files during development
    if app.config['DEBUG']:
        app.wsgi_app = SharedDataMiddleware(app.wsgi_app, {
            '/uploads': os.path.join(os.path.dirname(__file__), 'uploads')
        })

# In your main app.py
if __name__ == '__main__':
    with app.app_context():
        db.create_all()
        configure_uploads(app)  # Add this line

    app.run(
        debug=True,
        host='0.0.0.0',
        port=80
    )