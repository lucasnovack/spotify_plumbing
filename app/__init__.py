from flask import Flask
from config import Config
import os

def create_app():
    template_path = os.path.join(os.path.dirname(__file__), '..', 'templates')
    static_path = os.path.join(os.path.dirname(__file__), '..', 'static')
    app = Flask(__name__, template_folder=template_path, static_folder=static_path)
    app.config.from_object(Config)
    
    from app.routes.auth_routes import auth_bp
    from app.routes.dashboard_routes import dashboard_bp
    from app.routes.stats_routes import stats_bp
    
    app.register_blueprint(auth_bp)
    app.register_blueprint(dashboard_bp)
    app.register_blueprint(stats_bp)

    return app