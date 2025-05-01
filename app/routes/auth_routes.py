from flask import Blueprint, redirect, request, render_template, session
from app.utils.spotify_auth import get_auth_url, get_spotify_client

auth_bp = Blueprint("auth", __name__, template_folder="../templates")

@auth_bp.route("/")
def index():
    auth_url = get_auth_url()
    return render_template("index.html", auth_url=auth_url)

@auth_bp.route("/callback")
def callback():
    sp_oauth = get_spotify_client().auth_manager
    code = request.args.get("code")
    token_info = sp_oauth.get_access_token(code)
    session["token_info"] = token_info
    return redirect("/dashboard")