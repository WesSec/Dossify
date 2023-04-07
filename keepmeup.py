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


# Create an app at https://developer.spotify.com/dashboard/applications
clientId = "<clientID>"
clientSecret = "<ClientSecret>"

# all values must be filled, if you like something to be empty (eg description, just put in a dot or remove it from json_data)
playlist_name = "<playlist name>"
playlist_description = "<playlist description>"
# only the ID, do not include "spotify:playlist:"
playlist_id = "<playlist ID>"
# Settings for intervallign and steps
interval = 0.5
max_interval = 30
backoff_factor = 2
decrease_factor = 0.5

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
    access_token = token_response.json()['access_token']
    refresh_token = token_response.json()['refresh_token']
    return access_token, refresh_token


def refresh_token2(refresh_token):
    auth_client = clientId + ":" + clientSecret
    auth_encode = 'Basic ' + base64.b64encode(auth_client.encode()).decode()

    headers = {
        'Authorization': auth_encode,
    }

    data = {
        'grant_type': 'refresh_token',
        'refresh_token': refresh_token
    }

    response = requests.post('https://accounts.spotify.com/api/token',
                             data=data, headers=headers)  # sends request off to spotify

    if (response.status_code == 200):  # checks if request was valid
        print("The request went through; we got a status 200; Spotify token refreshed")
        response_json = response.json()
        new_expire = response_json['expires_in']
        print("the time left on new token is: " + str(new_expire / 60) + "min")  # says how long
        return response_json["access_token"]
    else:
        print("ERROR! The response we got was: " + str(response))


def get_playlist_name(playlist_id, token):
    global interval
    headers = {
            'Content-Type': 'application/json',
            'Authorization': f'Bearer {token}',
        }
    response = requests.get(
            f'https://api.spotify.com/v1/playlists/{playlist_id}', headers=headers)
    
    #Ratelimit protection
    if response.status_code == 429:
        # API rate limit reached, sleep for the current interval
        time.sleep(interval)
        
        # Increase the interval for the next call
        interval = min(interval * backoff_factor, max_interval)
        print(f"[i] ratelimit hit, increased interfal to {interval}")
        return False
    
    
    if response.json()['name'] == playlist_name:
        # API call was successful, decrease the interval slightly
        interval = max(interval * decrease_factor, 1)
        return False
    else:
        return True

if __name__ == "__main__":
    token_url, token_payload, token_headers = authorize()
    token, refresh_tok = refresh_token(token_url, token_payload, token_headers)
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
        if get_playlist_name(playlist_id, token):
        # Update playlist name
            response = requests.put(
                f'https://api.spotify.com/v1/playlists/{playlist_id}', headers=headers, json=json_data)
            if response.status_code == 200:
                print(f"[i] {time.strftime('%H:%M', time.localtime(time.time()))} - Updated name for playlist {playlist_name}")
        else:
            # print(f"[i] playlist still intact")
            time.sleep(interval)
            pass
