import spotipy
from spotipy.oauth2 import SpotifyClientCredentials
from dotenv import load_dotenv
import os

load_dotenv()

sp = spotipy.Spotify(auth_manager=SpotifyClientCredentials(client_id=os.environ["CLIENT_ID"],
                                                           client_secret=os.environ["CLIENT_SECRET"]))

print(sp)