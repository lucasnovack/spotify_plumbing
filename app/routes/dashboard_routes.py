from flask import Blueprint, redirect, render_template, session

dashboard_bp = Blueprint("dashboard", __name__, template_folder="../templates")

@dashboard_bp.route("/dashboard")
def dashboard():
    if "token_info" not in session:
        return redirect("/")
    return render_template("dashboard.html")