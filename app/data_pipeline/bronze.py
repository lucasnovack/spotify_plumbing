import os
import json
from datetime import datetime
from app.utils.spotify_auth import get_spotify_client

def fetch_and_save_bronze_data(data_type="tracks"):
    """
    Get and save raw data.
    
    Args:
        data_type (str): Type ('tracks' or 'artists').
    """
    sp = get_spotify_client()
    timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
    
    if data_type == "tracks":
        data = sp.current_user_top_tracks(limit=50, time_range="medium_term")
        output_path = f"data/bronze/top_tracks_{timestamp}.json"
    elif data_type == "artists":
        data = sp.current_user_top_artists(limit=50, time_range="medium_term")
        output_path = f"data/bronze/top_artists_{timestamp}.json"
    else:
        raise ValueError("Invalid data_type. Use 'tracks' or 'artists'.")
    
    os.makedirs(os.path.dirname(output_path), exist_ok=True)
    with open(output_path, "w") as f:
        json.dump(data, f, indent=4)
    
    print(f"Bronze data saved to: {output_path}")
    return output_path