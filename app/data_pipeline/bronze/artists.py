import os
import json
from datetime import datetime
from app.utils.spotify_auth import get_spotify_client

def fetch_and_save_bronze_artists():
    """
    Fetch and save raw top artists data from Spotify.
    
    Returns:
        str: Path to the saved JSON file.
    """
    sp = get_spotify_client()
    timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
    
    data = sp.current_user_top_artists(limit=50, time_range="medium_term")
    output_path = f"data/bronze/top_artists_{timestamp}.json"
    
    os.makedirs(os.path.dirname(output_path), exist_ok=True)
    with open(output_path, "w") as f:
        json.dump(data, f, indent=4)
    
    print(f"Bronze artists data saved to: {output_path}")
    return output_path