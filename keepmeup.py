#####################################################################################################################
# This is a kinda ugly script to automatically update your spotify playlist name to prefent fake abuse takedowns    #
# 1. Register an spotify app at https://developer.spotify.com/dashboard/applications,                               #
# 2. Set the callback url to http://localhost:8888/callback/                                                        #
# 3. Set the client ID and Secret in this file                                                                      #
# 4. Fill in the spotify playlist id, name and description in this file                                             #
# 5. run keepmeup.py, open the url in your browser                                                                  #
# 6. After logging in, open the link printed in console, a webserver will be started to fetch the code for you      #
# 7. The script will now check for changes (aka takedowns) and reset your playlist                                  #                                                                                                         #
#####################################################################################################################


import requests
import time
import base64
import http.server
import socketserver
from urllib.parse import urlparse, parse_qs
import logging

logging.basicConfig(
    format="[%(asctime)s] %(levelname)s: %(message)s",
    datefmt="%Y-%m-%d %H:%M:%S",
    level=logging.DEBUG,
)

# Constants
CLIENT_ID = ""  # Your spotify app ID
CLIENT_SECRET = ""  # Your spotify app Secret
PLAYLIST_NAME = ""  # Desired Playlist name
PLAYLIST_DESCRIPTION = (
    "2"  # Playlist description (not checked for changes, but will be empty if not set)
)
PLAYLIST_ID = ""  # Playlist ID (without the spotify:playlist prefix(!)
INTERVAL = 45 # Desired interval, a lower value may result in earlier rate limits
REDIRECT_URI = "http://localhost:8888/callback/"
SCOPES = "playlist-modify-public"


AUTH_CODE = None


def handle_rate_limit(response):
    """Handles rate-limit responses (HTTP 429)"""
    retry_after = int(response.headers.get("Retry-After", INTERVAL))
    logging.error(f"Rate-limited, waiting for {retry_after} seconds.")
    time.sleep(retry_after)


class RequestHandler(http.server.SimpleHTTPRequestHandler):
    def do_GET(self):
        global AUTH_CODE
        self.send_response(200)
        self.send_header("Content-type", "text/html")
        self.end_headers()
        query = urlparse(self.path).query
        params = parse_qs(query)
        AUTH_CODE = params.get("code", [None])[0]
        self.wfile.write(b"OK")


def start_server():
    PORT = 8888
    handler = RequestHandler
    with socketserver.TCPServer(("", PORT), handler) as httpd:
        logging.debug(f"Serving at port {PORT}")
        while AUTH_CODE is None:
            httpd.handle_request()  # This will handle a single request


def authorize():
    # Set up the authentication parameters
    client_id = CLIENT_ID
    client_secret = CLIENT_SECRET
    redirect_uri = "http://localhost:8888/callback/"
    scopes = "playlist-modify-public"  # Replace with the desired scopes
    auth_url = "https://accounts.spotify.com/authorize"
    token_url = "https://accounts.spotify.com/api/token"

    # Redirect the user to the Spotify login page to obtain an authorization code
    auth_payload = {
        "client_id": client_id,
        "response_type": "code",
        "redirect_uri": redirect_uri,
        "scope": scopes,
    }
    auth_response = requests.get(auth_url, params=auth_payload)

    if auth_response.status_code == 429:
        handle_rate_limit(auth_response)
        return authorize()

    print(f"Open {auth_response.url} in your browser")

    # Start the server to capture the auth code
    start_server()

    # Debugging print to confirm auth code receipt
    logging.debug(f"Received Auth code: {AUTH_CODE}")

    authorization_code = AUTH_CODE

    # Exchange the authorization code for an access token
    token_payload = {
        "grant_type": "authorization_code",
        "code": authorization_code,
        "redirect_uri": redirect_uri,
        "client_id": client_id,
        "client_secret": client_secret,
    }

    try:
        token_response = requests.post(
            token_url,
            data=token_payload,
            headers={
                "Authorization": f'Basic {base64.b64encode(f"{client_id}:{client_secret}".encode()).decode()}'
            },
        )

        token_response.raise_for_status()

        token_data = token_response.json()
        access_token = token_data["access_token"]
        refresh_token = token_data["refresh_token"]

        # Debugging prints to confirm token acquisition (Avoid printing in production!)
        logging.debug(f"Access Token: {access_token}") 
        logging.debug(f"Refresh Token: {refresh_token}")

        return access_token, refresh_token

    except requests.RequestException as e:
        print(f"Failed to exchange auth code for tokens: {e}")


def refresh_token(refresh_tok):
    headers = {
        "Authorization": f'Basic {base64.b64encode(f"{CLIENT_ID}:{CLIENT_SECRET}".encode()).decode()}'
    }
    data = {"grant_type": "refresh_token", "refresh_token": refresh_tok}
    response = requests.post(
        "https://accounts.spotify.com/api/token", data=data, headers=headers
    )
    if response.status_code == 429:
        handle_rate_limit(response)
        return refresh_token(refresh_tok)
    elif response.status_code != 200:
        response.raise_for_status()
    return response.json()["access_token"]


def get_playlist_name(token, current_refresh_token):
    headers = {
        "Content-Type": "application/json",
        "Authorization": f"Bearer {token}",
    }
    response = requests.get(
        f"https://api.spotify.com/v1/playlists/{PLAYLIST_ID}", headers=headers
    )

    if response.status_code == 401:
        logging.debug("Token expired, refreshing...")
        token = refresh_token(current_refresh_token)
        return False, token
    elif response.status_code == 429:  # Rate limit
        handle_rate_limit(response)
        return get_playlist_name(token)
    elif response.status_code != 200:
        response.raise_for_status()

    if response.json()["name"] == PLAYLIST_NAME:
        logging.debug("Playlist name is still intact.")
        return False, token
    else:
        logging.debug(f"Playlist name changed, reverting back to original")
        return True, token


if __name__ == "__main__":
    access_token, current_refresh_token = authorize()

    while True:
        headers = {
            "Content-Type": "application/json",
            "Authorization": f"Bearer {access_token}",
        }
        json_data = {
            "name": PLAYLIST_NAME,
            "description": PLAYLIST_DESCRIPTION,
            "public": True,
        }
        update_required, access_token = get_playlist_name(
            access_token, current_refresh_token
        )
        if update_required:
            response = requests.put(
                f"https://api.spotify.com/v1/playlists/{PLAYLIST_ID}",
                headers=headers,
                json=json_data,
            )
            if response.status_code == 429:
                handle_rate_limit(response)
                continue
            elif response.status_code == 200:
                logging.info(
                    f"Updated name for playlist {PLAYLIST_NAME}"
                ) 
        time.sleep(INTERVAL)
