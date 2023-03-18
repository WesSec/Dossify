import requests
import time
import imaplib
import re
from python3_anticaptcha import NoCaptchaTaskProxyless

# account credentials
email = "<imap username>"
email_password = "<imap password>"
imap_server = "<imap server>"

# Anticaptcha key, get one at https://anti-captcha.com/
ANTICAPTCHA_KEY = "<AntiCaptcha Key>"
# Spotify report sitekey
SITE_KEY = '6LcJ6ioaAAAAAGwTynFHPkstaq5chwiDzOm841E6'

# Page url where to 'solve' the captcha
PAGE_URL = 'https://support.spotify.com/us/content-policy-reporting/'

# Set up requests session
session = requests.Session()


def get_auth_code_from_email():
    # Connect to the IMAP server
    mail = imaplib.IMAP4_SSL(imap_server)
    mail.login(email, email_password)
    mail.select('inbox')
    print("[i] Waiting for email to arrive ...")
    while True:
        # Fetch the unseen messages from Spotify
        status, messages = mail.search(None, '(UNSEEN FROM "spotify.com")')
        if messages[0]:
            messages = messages[0].split(b' ')
            # Process the messages here...
            for msg_id in messages:
                _, msg_data = mail.fetch(msg_id, '(BODY[TEXT])')
                msg_str = msg_data[0][1].decode('utf-8')

                # Use regex to find a 8-digit code in the message body
                code_match = re.search(r'\b\d{8}\b', msg_str)
                if code_match:
                    auth_code = code_match.group(0)

                    # Mark the message as read
                    mail.store(msg_id, '+FLAGS', '\\Seen')
                    mail.close()
                    mail.logout()

                    # Return the authentication code
                    print("[!] Authentication code found in email: " + auth_code)

                    return auth_code
        # Wait for a few seconds before checking again
        time.sleep(1)


def takedown(playlistid):
    # Request authorizatio code
    r = session.post(
        url="https://contentreporting-api.spotify.com/v2/content-policy-report-form/get-code", json={"email": email})
    # Save ResourceURI, it is needed in the takedown call
    resourceURI = r.json()["resourceUri"]
    # Get the authentication code from the email, its a different function that parses the email message
    code = get_auth_code_from_email()
    # Post the code for validation
    session.post(url="https://contentreporting-api.spotify.com/v2/content-policy-report-form/validate-code",
                 json={"email": email, "resourceUri": resourceURI, "code": code})

    # Get string for solve captcha, and other info.
    print("[i] Solving captcha...")
    user_answer = NoCaptchaTaskProxyless.NoCaptchaTaskProxyless(anticaptcha_key=ANTICAPTCHA_KEY)\
        .captcha_handler(websiteURL=PAGE_URL,
                         websiteKey=SITE_KEY)
    print("[i] Captcha solved!")
    # Prepare the json for takedownn call
    takedownjson = {"verificationDetails": {"resourceUri": resourceURI, "code": code, "googleRecaptchaToken": user_answer['solution']['gRecaptchaResponse']}, "report": {
        "reporterEmail": email, "reporterCountryCode": "us", "productUri": f"spotify:playlist:{playlistid}", "contentType": "CONTENT_TYPE_PLAYLIST_TITLE", "reason": "REASON_HATEFUL_OR_ABUSIVE", "reporterUserAgent": "", "experiments": [], "queryParams": {}}}
    # Send takedown request

    r = session.post(
        url="https://contentreporting-api.spotify.com/v2/content-policy-report-form/submit-external-report", json=takedownjson)
    # If http request succeeds, show text
    if r.status_code == 200 or r.status_code == 201:
        print("[!] Playlist taken down successfully, costs of takedown: $ " +
              str(user_answer['cost']))
        # Report correct captcha back to anti-captcha.com (this improves speed for the next request)
        response = requests.post('https://api.anti-captcha.com/reportCorrectRecaptcha', headers={'Accept': 'application/json','Content-Type': 'application/json',}, json={'clientKey': ANTICAPTCHA_KEY, 'taskId': user_answer['taskId'],})
    else:
        print(r.text)
        # if the captcha key is incorrect (CHECK SITE KEY!!!) report to anticaptcha to get a refund
        if "CAPTCHA" in r.text:
            print(requests.post('https://api.anti-captcha.com/reportIncorrectRecaptcha', headers={'Accept': 'application/json','Content-Type': 'application/json',}, json={'clientKey': ANTICAPTCHA_KEY, 'taskId': user_answer['taskId'],}).json())
            # very ugly, but try this playlist agian
            takedown(playlistid)
        


if __name__ == '__main__':
    # Read playlists
    with open('playlists.txt') as file:
        # Loop through the urls
        urls = [line.strip() for line in file]
        for url in urls:
            # Call takedown function for url
            takedown(url)
