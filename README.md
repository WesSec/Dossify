# Dossify: Denial of Service on Public Playlists
This is a proof-of-concept (POC) for a design flaw discovered in Spotify's playlist reporting feature. The flaw allows an attacker to cause a denial of service (DoS) / availability issue by exploiting a weakness in the playlist reporting mechanism, effectively making a playlist disappear until the creator changes the name of the playlist.

## Background
Spotify allows users to create and share public playlists with other users. Users can report violations in these playlists, such as inappropriate content or copyright infringement. Spotify's reporting mechanism is designed to prevent abuse and maintain the quality of the platform. However, this POC demonstrates a weakness in the reporting mechanism that can be exploited for malicious purposes.

I created this POC as some of my (popular) public playlists are constantly being taken down by various parties. I believe this is done for the reason they want to have their playlist on top of the search results, generating more conversions for the artists in their playlists.

When a playlist 'gets taken down', just the name of the playlist is removed, resulting in it not showing up anymore in search results or people's sidebar. The playlist itself will persist and pop back up when the owner of the playlist adds the name again. This is becoming a cat-and-mouse game.

## Description
The flaw allows an attacker to flood Spotify's servers with a large number of fake reports against a public playlist. This can cause the playlist to be taken down by Spotify's automated system, effectively denying access to legitimate users who rely on the playlist.

The root cause of the flaw is the lack of appropriate measurements to prevent a DoS attack on public playlists. Spotify's reporting mechanism does not have sufficient safeguards to prevent a malicious user from flooding the system with fake reports resulting in automatic takedowns.

## POC Details
This POC demonstrates how an attacker can use a simple script to flood Spotify's servers with fake reports against a public playlist, effectively taking it down immediately.

The POC code is available in the `dossify.py` file. The file contains detailed instructions on how to use the script, including the required parameters and configuration options.

1. Install requirements `pip install -r requirements.txt'
2. Set up your email provider and anti-captcha.com API key in `dossify.py` file
2. Enter the playlist id's you want to take down in `playlists.txt` (only the ID, remove the domain and si parameter)
3. Run  `python3 dossify.py`
4. ....
5. Watch the playlist disappear

### Email verification
Spotify requires email verification (no Spotify account is needed on the email address), therefore create some alias mail somewhere and put in the IMAP details in the POC.

### Captcha
Another control in place is Recaptchav2, which is an outdated method for defending against bots/scripts. This POC uses anti-captcha.com to bypass the challenges, which cost about $0.002 per challenge/playlist takedown. Throw a fiver at it and add the API key to the script. You can also edit the script and use your own method for bypassing the captchas.

## Mitigation

To "keep your playlist online" I created another script called `keepmeup.py` which will be added later to this repository. This script will continuously update the name of the playlist, putting it back 'online' after fake reports.

## Reporting and Disclosure
The flaw was reported to Spotify's security team through their vulnerability disclosure problem, but it was not considered a security vulnerability. As a result, the flaw was not patched, and the POC is being published to raise awareness about the issue.

If you are a Spotify user, you should be aware of the risk of DoS attacks on public playlists. To protect yourself, avoid relying on a single public playlist and consider creating your own private playlists instead before your favorite public playlist somehow gets yeeted off Spotify.

## Disclaimer
This POC is for educational and research purposes only. Do not use it to harm or damage any systems or networks. The author assumes no responsibility for any misuse of the code or the information provided in this README.

## License
This POC is licensed under the MIT License. See the LICENSE file for details.