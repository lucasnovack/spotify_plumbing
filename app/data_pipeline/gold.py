import pandas as pd
import os
import json

def process_gold_data(silver_file):
    df = pd.read_csv(silver_file)
    
    stats = {
        "total_tracks": len(df),
        "avg_popularity": df["popularity"].mean(),
        "avg_duration_min": df["duration_min"].mean(),
        "top_artist": df["artist_name"].value_counts().idxmax(),
        "top_album": df["album.name"].value_counts().idxmax()
    }
    
    top_tracks = df[["name", "artist_name", "popularity"]].sort_values(by="popularity", ascending=False).head(5)
    
    timestamp = silver_file.split("_")[-1].replace(".csv", "")
    output_path = f"data/gold/gold_stats_{timestamp}.json"
    os.makedirs(os.path.dirname(output_path), exist_ok=True)
    
    with open(output_path, "w") as f:
        json.dump({"stats": stats, "top_tracks": top_tracks.to_dict(orient="records")}, f, indent=4)
    
    return output_path