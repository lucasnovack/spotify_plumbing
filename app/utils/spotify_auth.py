import spotipy
from spotipy.oauth2 import SpotifyOAuth
from config import Config

def get_spotify_client():
    scope = "user-top-read user-library-read"
    sp_oauth = SpotifyOAuth(
        client_id=Config.SPOTIFY_CLIENT_ID,
        client_secret=Config.SPOTIFY_CLIENT_SECRET,
        redirect_uri=Config.SPOTIFY_REDIRECT_URI,
        scope=scope
    )
    return spotipy.Spotify(auth_manager=sp_oauth)

def get_auth_url():
    sp_oauth = SpotifyOAuth(
        client_id=Config.SPOTIFY_CLIENT_ID,
        client_secret=Config.SPOTIFY_CLIENT_SECRET,
        redirect_uri=Config.SPOTIFY_REDIRECT_URI,
        scope="user-top-read user-library-read"
    )
    return sp_oauth.get_authorize_url()