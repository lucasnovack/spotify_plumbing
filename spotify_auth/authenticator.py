import os
import logging
from datetime import datetime, timedelta
from typing import Optional
import requests
from dotenv import load_dotenv


class SpotifyAuthenticationError(Exception):
    "Basic auth error"


class InvalidCredentialsError(SpotifyAuthenticationError):
    "Basic credential error"


class AuthenticationRequestError(SpotifyAuthenticationError):
    "Basic request auth error"


logging.basicConfig(
    format="%(asctime)s - %(name)s - %(levelname)s - %(message)s", level=logging.INFO
)

logger = logging.getLogger(__name__)


class SpotifyAuthenticator:
    _TOKEN_URL = "https://accounts.spotify.com/api/token"
    _TOKEN_EXPIRY_BUFFER = 300

    def __init__(self):
        load_dotenv()
        self.client_id = os.environ["CLIENT_ID"]
        self.client_secret = os.environ["CLIENT_SECRET"]
        self._access_token: Optional[str] = None
        self._token_expiry: Optional[datetime] = None

        self._validate_credentials()

        logger.info("SpotifyAuthenticator initialized successfully")

    def _validate_credentials(self) -> None:
        if not self.client_id or not self.client_secret:
            logger.error(
                "Your credentials are missing, please configure your variables!"
            )
            raise InvalidCredentialsError(
                "MISSING CREDENTIALS -> VERIFY YOUR .ENV FILE!"
            )

    @property
    def access_token(self) -> str:
        if self._token_expired:
            logger.info("Token got expired, generating a new one...")
            self._request_new_token()
        return self._access_token

    @property
    def _token_expired(self) -> bool:
        if not self._token_expiry:
            return True
        return datetime.now() > (
            self._token_expiry - timedelta(seconds=self._TOKEN_EXPIRY_BUFFER)
        )

    def _request_new_token(self) -> None:
        auth_header = {"Content-Type": "application/x-www-form-urlencoded"}

        auth_data = {"grant_type": "client_credentials"}

        try:
            response = requests.post(
                url=self._TOKEN_URL,
                headers=auth_header,
                auth=(self.client_id, self.client_secret),
                data=auth_data,
                timeout=10,
            )

            response.raise_for_status()
        except requests.exceptions.RequestException as e:
            logger.error(f"Error while authentication request -> {e}")
            raise AuthenticationRequestError(
                f"Failed while authenticating -> {e}"
            ) from e

        try:
            token_data = response.json()
            self._access_token = token_data["access_token"]
            expires_in = token_data["expires_in"]
            self._token_expiry = datetime.now() + timedelta(seconds=expires_in)
            logger.info("Bearer token assigned!")
        except KeyError as e:
            logger.error("Bearer token couldn't be retrieved!")
            raise AuthenticationRequestError("Invalid response from Spotify API") from e

    def get_auth_header(self) -> dict:
        return {"Authorization": f"Bearer {self.access_token}"}
