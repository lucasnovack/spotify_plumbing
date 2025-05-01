from flask import Flask
from config import Config
import os

def create_app():
    template_path = os.path.join(os.path.dirname(__file__), '..', 'templates')
    static_path = os.path.join(os.path.dirname(__file__), '..', 'static')
    app = Flask(__name__, template_folder=template_path, static_folder=static_path)
    app.config.from_object(Config)

    from app import routes
    app.register_blueprint(routes.bp)

    return app