import pandas as pd
import os

def process_silver_data(bronze_file):
    df = pd.read_json(bronze_file)
    
    tracks = df["items"]
    
    df_tracks = pd.json_normalize(tracks)
    
    df_silver = df_tracks[[
        "id", "name", "artists", "album.name", "popularity", "duration_ms"
    ]].copy()
    
    df_silver["artist_name"] = df_silver["artists"].apply(lambda x: x[0]["name"])
    df_silver = df_silver.drop(columns=["artists"])
    
    df_silver["duration_min"] = df_silver["duration_ms"] / 60000
    
    timestamp = bronze_file.split("_")[-1].replace(".json", "")
    output_path = f"data/silver/silver_tracks_{timestamp}.csv"
    os.makedirs(os.path.dirname(output_path), exist_ok=True)
    df_silver.to_csv(output_path, index=False)
    
    return output_path