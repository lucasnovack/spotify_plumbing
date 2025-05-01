from flask import Blueprint, redirect, render_template, session
from app.utils.spotify_auth import get_spotify_client
from app.utils.file_cleanup import cleanup_old_files
from app.data_pipeline.bronze import fetch_and_save_bronze_data
from app.data_pipeline.silver import process_silver_data
from app.data_pipeline.gold import process_gold_data
import json

stats_bp = Blueprint("stats", __name__, template_folder="../templates")

@stats_bp.route("/stats")
def stats():
    if "token_info" not in session:
        return redirect("/")
    
    cleanup_old_files("data/bronze/", max_files=5, file_extension="*.json")
    cleanup_old_files("data/silver/", max_files=5, file_extension="*.csv")
    cleanup_old_files("data/gold/", max_files=5, file_extension="*.json")
    
    bronze_file = fetch_and_save_bronze_data()
    silver_file = process_silver_data(bronze_file)
    gold_file = process_gold_data(silver_file)
    
    with open(gold_file, "r") as f:
        stats_data = json.load(f)
    
    return render_template("stats.html", stats=stats_data["stats"], top_tracks=stats_data["top_tracks"])

@stats_bp.route("/top-artists")
def top_artists():
    if "token_info" not in session:
        return redirect("/")
    
    cleanup_old_files("data/bronze/", max_files=5, file_extension="*.json")
    
    sp = get_spotify_client()
    top_artists = sp.current_user_top_artists(limit=10, time_range="medium_term")
    
    artists = [
        {"name": artist["name"], "popularity": artist["popularity"], "genres": ", ".join(artist["genres"])}
        for artist in top_artists["items"]
    ]
    
    return render_template("top_artists.html", artists=artists)

@stats_bp.route("/general-stats")
def general_stats():
    if "token_info" not in session:
        return redirect("/")
    
    cleanup_old_files("data/bronze/", max_files=5, file_extension="*.json")
    cleanup_old_files("data/silver/", max_files=5, file_extension="*.csv")
    cleanup_old_files("data/gold/", max_files=5, file_extension="*.json")
    
    bronze_file = fetch_and_save_bronze_data()
    silver_file = process_silver_data(bronze_file)
    gold_file = process_gold_data(silver_file)
    
    with open(gold_file, "r") as f:
        stats_data = json.load(f)
    
    return render_template("general_stats.html", stats=stats_data["stats"])