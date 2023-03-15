#####################################################################################################################
# This is a kinda ugly script to automatically update your spotify playlist name to prefent fake abuse takedowns    #
# 1. Register an spotify app at https://developer.spotify.com/dashboard/applications,                               #
# 2. Set the callback url to http://localhost:8888/callback/ or anything you like, this is a manual step atm        #
# 3. Set the client ID and Secret in this file                                                                      #
# 4. Fill in the spotify playlist id, name and description in this file                                             #
# 5. run main.py, open the url in your browser                                                                      #
# 6. After logging in, copy the "code" parameter from your url and put it in the console                            #
# 7. ???                                                                                                            #
# 8. profit                                                                                                         #
#####################################################################################################################


import requests
import time
import base64
import webbrowser


# Create an app at https://developer.spotify.com/dashboard/applications
clientId = "<clientID>"
clientSecret = "<ClientSecret>"

# all values must be filled, if you like something to be empty (eg description, just put in a dot or remove it from json_data)
playlist_name = "<Desired playlist name>"
playlist_description = "You cant take me down"
# only the ID, do not include "spotify:playlist:"
playlist_id = "<playlistID>"
# Interval on how often to update the playlist name, spotify's ratelimit is calculated in a rolling 30 sec window, so 30 secs should always be fine
interval = 60


def authorize():
    # Set up the authentication parameters
    client_id = clientId
    client_secret = clientSecret
    # Replace with your own redirect URI
    redirect_uri = 'http://localhost:8888/callback/'
    scopes = 'playlist-modify-public'  # Replace with the desired scopes
    auth_url = 'https://accounts.spotify.com/authorize'
    token_url = 'https://accounts.spotify.com/api/token'

    # Redirect the user to the Spotify login page to obtain an authorization code
    auth_payload = {
        'client_id': client_id,
        'response_type': 'code',
        'redirect_uri': redirect_uri,
        'scope': scopes
    }
    auth_response = requests.get(auth_url, params=auth_payload)
    print(f"Open {auth_response.url} in your browser")

    # After the user logs in and grants permission, they will be redirected to the callback URL with an authorization code
    authorization_code = input('Enter the authorization code: ')

    # Exchange the authorization code for an access token
    token_payload = {
        'grant_type': 'authorization_code',
        'code': authorization_code,
        'redirect_uri': redirect_uri
    }
    token_headers = {
        'Authorization': f'Basic {base64.b64encode(f"{client_id}:{client_secret}".encode()).decode()}'
    }
    return token_url, token_payload, token_headers


def refresh_token(token_url, token_payload, token_headers):
    token_response = requests.post(
        token_url, data=token_payload, headers=token_headers)
    return token_response.json()['access_token']


if __name__ == "__main__":
    token_url, token_payload, token_headers = authorize()
    token = refresh_token(token_url, token_payload, token_headers)
    last_refresh_time = time.time()
    while True:
        # Prepare headers
        headers = {
            'Content-Type': 'application/json',
            'Authorization': f'Bearer {token}',
        }
        json_data = {
            'name': f'{playlist_name}',
            'description': f'{playlist_description}',
            'public': True,
        }
        # Update playlist name
        response = requests.put(
            f'https://api.spotify.com/v1/playlists/{playlist_id}', headers=headers, json=json_data)
        # if you like to debug:
        # print(response.status_code, response.text)
        if response.status_code == 200:
            print(
                f"[i] {time.strftime('%H:%M', time.localtime(time.time()))} - Updated name for playlist {playlist_name}")
        if response.status_code == 403:
            print(
                "[!] Something went wrong with authorizing, please check your clientID and Client Secret")
            break
        # If ratelimit is hit, sleep some more
        if response.status_code == 429:
            print("[!] Ratelimit hit, pausing for 30 more secs")
            time.sleep(30)
        # I think tokens need to be refreshed every hour, so
        if time.time() - last_refresh_time >= 3480:  # 58 minutes in seconds
            token = refresh_token(token_url, token_payload, token_headers)
            last_refresh_time = time.time()  # Update last refresh time
        # if for some reason the token fails, get a new one too
        if response.status_code == 401:
            print("[!] Token expired")
            token = refresh_token(token_url, token_payload, token_headers)
        # Do some sleepy
        time.sleep(interval)
