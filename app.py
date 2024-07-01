from flask import Flask, redirect, url_for, session, request, jsonify, send_from_directory
import google.oauth2.credentials
import google_auth_oauthlib.flow
import googleapiclient.discovery
import os
import requests
from dotenv import load_dotenv
import base64
import html
from datetime import datetime, timedelta
from email.mime.text import MIMEText
from email.mime.multipart import MIMEMultipart
from bs4 import BeautifulSoup
import re
import urllib.parse
import shutil
import json

# Load environment variables from .env file (if using .env)
load_dotenv()

# Allow insecure transport for local development
os.environ['OAUTHLIB_INSECURE_TRANSPORT'] = '1'

app = Flask(__name__)
app.secret_key = os.environ.get('FLASK_SECRET_KEY', 'default_key_for_dev')  # Retrieve the secret key from environment variable or use a default for development

# OAuth 2.0 Client IDs and secrets
CLIENT_SECRETS_FILE = 'client_secrets.json'  # Replace with the path to your client_secrets.json file

SCOPES = ['https://www.googleapis.com/auth/gmail.readonly']
API_SERVICE_NAME = 'gmail'
API_VERSION = 'v1'

@app.route('/')
def index():
    try:
        if 'credentials' not in session:
            return redirect('authorize')

        credentials = google.oauth2.credentials.Credentials(
            **session['credentials'])

        gmail = googleapiclient.discovery.build(
            API_SERVICE_NAME, API_VERSION, credentials=credentials)

        profile = gmail.users().getProfile(userId='me').execute()
        email_address = profile['emailAddress']

        print("SUCCESS")
        return jsonify({"email_address": email_address})
    except Exception as e:
        print(f"FAILURE: {e}")
        return jsonify({"error": str(e)})

@app.route('/authorize')
def authorize():
    try:
        flow = google_auth_oauthlib.flow.Flow.from_client_secrets_file(
            CLIENT_SECRETS_FILE, scopes=SCOPES)

        flow.redirect_uri = url_for('oauth2callback', _external=True)

        # Generate the authorization URL and state
        authorization_url, state = flow.authorization_url(
            access_type='offline',
            include_granted_scopes='true')

        # Store the state in the session so that the callback can verify the auth server response.
        session['state'] = state
        print(f"Stored state: {state}")  # Log the stored state
        print(f"Authorization URL: {authorization_url}")  # Log the authorization URL

        return redirect(authorization_url)
    except Exception as e:
        print(f"FAILURE: {e}")
        return jsonify({"error": str(e)})

@app.route('/oauth2callback')
def oauth2callback():
    try:
        # Retrieve the state from the session
        stored_state = session.get('state')
        print(f"Stored state: {stored_state}")  # Log the stored state

        # Retrieve the state from the authorization response
        authorization_response = request.url
        parsed_url = urllib.parse.urlparse(authorization_response)
        query_params = urllib.parse.parse_qs(parsed_url.query)
        received_state = query_params.get('state', [None])[0]
        print(f"Received state: {received_state}")  # Log the received state

        if stored_state != received_state:
            print("FAILURE: State mismatch error")
            return jsonify({"error": "State mismatch error"}), 400

        flow = google_auth_oauthlib.flow.Flow.from_client_secrets_file(
            CLIENT_SECRETS_FILE, scopes=SCOPES, state=stored_state)
        flow.redirect_uri = url_for('oauth2callback', _external=True)

        # Log the redirect URI for verification
        print(f"OAuth2 Callback URI: {flow.redirect_uri}")

        # Use the authorization server's response to fetch the OAuth 2.0 tokens.
        flow.fetch_token(authorization_response=authorization_response)

        credentials = flow.credentials
        token_expiry = credentials.expiry
        refresh_token_expiry = None

        if token_expiry:
            token_expiry_str = token_expiry.strftime('%m/%d/%Y %H:%M:%S')
            # Assuming refresh token expiry is typically 1 hour after the token is fetched
            refresh_token_expiry = token_expiry + timedelta(seconds=3600)
            refresh_token_expiry_str = refresh_token_expiry.strftime('%m/%d/%Y %H:%M:%S')
        else:
            token_expiry_str = 'No expiration time available'
            refresh_token_expiry_str = 'No refresh token expiration time available'

        session['credentials'] = {
            'token': credentials.token,
            'refresh_token': credentials.refresh_token,
            'token_uri': credentials.token_uri,
            'client_id': credentials.client_id,
            'client_secret': credentials.client_secret,
            'scopes': credentials.scopes,
            'token_expiry': token_expiry_str,
            'refresh_token_expiry': refresh_token_expiry_str
        }

        print("SUCCESS")
        return redirect(url_for('tokens'))
    except Exception as e:
        print(f"FAILURE: {e}")
        return jsonify({"error": str(e)})

@app.route('/tokens')
def tokens():
    try:
        if 'credentials' not in session:
            return redirect('authorize')

        credentials_info = session.get('credentials')
        print("SUCCESS")
        return jsonify(credentials_info)
    except Exception as e:
        print(f"FAILURE: {e}")
        return jsonify({"error": str(e)})

@app.route('/emails')
def list_emails():
    try:
        if 'credentials' not in session:
            return redirect('authorize')

        start_date = request.args.get('start_date')
        end_date = request.args.get('end_date')
        
        if not start_date or not end_date:
            print("FAILURE: Please provide both start_date and end_date in the format YYYY-MM-DD")
            return jsonify({"error": "Please provide both start_date and end_date in the format YYYY-MM-DD"}), 400
        
        try:
            start_date = datetime.strptime(start_date, '%Y-%m-%d')
            end_date = datetime.strptime(end_date, '%Y-%m-%d')
        except ValueError:
            print("FAILURE: Invalid date format. Please use YYYY-MM-DD")
            return jsonify({"error": "Invalid date format. Please use YYYY-MM-DD"}), 400

        credentials = google.oauth2.credentials.Credentials(
            **session['credentials'])

        gmail = googleapiclient.discovery.build(
            API_SERVICE_NAME, API_VERSION, credentials=credentials)

        query = f"after:{start_date.strftime('%Y/%m/%d')} before:{end_date.strftime('%Y/%m/%d')}"
        
        email_data = []
        page_token = None

        while True:
            if page_token:
                results = gmail.users().messages().list(userId='me', q=query, pageToken=page_token).execute()
            else:
                results = gmail.users().messages().list(userId='me', q=query).execute()
            
            messages = results.get('messages', [])
            for message in messages:
                msg = gmail.users().messages().get(userId='me', id=message['id']).execute()
                payload = msg['payload']
                headers = payload['headers']

                email_info = {}

                for header in headers:
                    if header['name'] == 'Subject':
                        email_info['subject'] = header['value']
                    if header['name'] == 'From':
                        email_info['from'] = extract_email(header['value'])
                    if header['name'] == 'Date':
                        email_info['date'] = header['value']
                    if header['name'] == 'To':
                        email_info['to'] = [extract_email(email) for email in header['value'].split(',')]

                body = ''
                if 'parts' in payload:
                    for part in payload['parts']:
                        if part['mimeType'] == 'text/plain' and 'data' in part['body']:
                            body = base64.urlsafe_b64decode(part['body']['data']).decode('utf-8')
                            break
                        elif part['mimeType'] == 'text/html' and 'data' in part['body']:
                            body = html.unescape(base64.urlsafe_b64decode(part['body']['data']).decode('utf-8'))
                            body = html_to_text(body)
                elif 'body' in payload and 'data' in payload['body']:
                    if payload['mimeType'] == 'text/plain':
                        body = base64.urlsafe_b64decode(payload['body']['data']).decode('utf-8')
                    elif payload['mimeType'] == 'text/html':
                        body = html.unescape(base64.urlsafe_b64decode(payload['body']['data']).decode('utf-8'))
                        body = html_to_text(body)

                email_info['body'] = clean_body(body)
                email_data.append(email_info)

            page_token = results.get('nextPageToken')
            if not page_token:
                break

        print("SUCCESS")
        return jsonify(email_data)
    except Exception as e:
        print(f"FAILURE: {e}")
        return jsonify({"error": str(e)})

@app.route('/download_attachments')
def download_attachments():
    try:
        if 'credentials' not in session:
            return redirect('authorize')

        start_date = request.args.get('start_date')
        end_date = request.args.get('end_date')
        
        if not start_date or not end_date:
            print("FAILURE: Please provide both start_date and end_date in the format YYYY-MM-DD")
            return jsonify({"error": "Please provide both start_date and end_date in the format YYYY-MM-DD"}), 400
        
        try:
            start_date = datetime.strptime(start_date, '%Y-%m-%d')
            end_date = datetime.strptime(end_date, '%Y-%m-%d')
        except ValueError:
            print("FAILURE: Invalid date format. Please use YYYY-MM-DD")
            return jsonify({"error": "Invalid date format. Please use YYYY-MM-DD"}), 400

        credentials = google.oauth2.credentials.Credentials(
            **session['credentials'])

        gmail = googleapiclient.discovery.build(
            API_SERVICE_NAME, API_VERSION, credentials=credentials)

        query = f"after:{start_date.strftime('%Y/%m/%d')} before:{end_date.strftime('%Y/%m/%d')}"
        
        attachments_info = []
        page_token = None

        download_folder = 'downloads'
        
        # Clear the download folder
        if os.path.exists(download_folder):
            for filename in os.listdir(download_folder):
                file_path = os.path.join(download_folder, filename)
                try:
                    if os.path.isfile(file_path) or os.path.islink(file_path):
                        os.unlink(file_path)
                    elif os.path.isdir(file_path):
                        shutil.rmtree(file_path)
                except Exception as e:
                    print(f'Failed to delete {file_path}. Reason: {e}')
        else:
            os.makedirs(download_folder)

        while True:
            if page_token:
                results = gmail.users().messages().list(userId='me', q=query, pageToken=page_token).execute()
            else:
                results = gmail.users().messages().list(userId='me', q=query).execute()

            messages = results.get('messages', [])
            for message in messages:
                msg = gmail.users().messages().get(userId='me', id=message['id']).execute()
                parts = msg.get('payload', {}).get('parts', [])

                for part in parts:
                    if part.get('filename'):
                        attachment_id = part['body']['attachmentId']
                        attachment = gmail.users().messages().attachments().get(
                            userId='me', messageId=message['id'], id=attachment_id).execute()
                        
                        data = base64.urlsafe_b64decode(attachment['data'].encode('UTF-8'))
                        
                        filepath = os.path.join(download_folder, part['filename'])
                        with open(filepath, 'wb') as f:
                            f.write(data)
                        
                        file_size = os.path.getsize(filepath)
                        print(f"Saved attachment {part['filename']} to {filepath} ({file_size} bytes)")
                        
                        attachments_info.append({
                            'filename': part['filename'],
                            'filepath': filepath,
                            'size': file_size
                        })

            page_token = results.get('nextPageToken')
            if not page_token:
                break

        # Save the attachments info to attachmentinfo.json
        with open('attachmentinfo.json', 'w') as json_file:
            json.dump(attachments_info, json_file, indent=4)

        print("SUCCESS")
        return jsonify(attachments_info)
    except Exception as e:
        print(f"FAILURE: {e}")
        return jsonify({"error": str(e)})

@app.route('/revoke')
def revoke():
    try:
        if 'credentials' not in session:
            return redirect('authorize')

        credentials = google.oauth2.credentials.Credentials(
            **session['credentials'])

        revoke = requests.post('https://oauth2.googleapis.com/revoke',
            params={'token': credentials.token},
            headers={'content-type': 'application/x-www-form-urlencoded'})

        status_code = getattr(revoke, 'status_code')
        if status_code == 200:
            print("SUCCESS")
            return jsonify({"message": "Credentials successfully revoked."})
        else:
            print("FAILURE: An error occurred.")
            return jsonify({"error": "An error occurred."})
    except Exception as e:
        print(f"FAILURE: {e}")
        return jsonify({"error": str(e)})

@app.route('/clear')
def clear_credentials():
    try:
        if 'credentials' in session:
            del session['credentials']
        print("SUCCESS")
        return jsonify({"message": "Credentials have been cleared."})
    except Exception as e:
        print(f"FAILURE: {e}")
        return jsonify({"error": str(e)})

def extract_email(email_string):
    """Extract the email address from a string."""
    match = re.search(r'[\w\.-]+@[\w\.-]+', email_string)
    return match.group(0) if match else None

def html_to_text(html_content):
    """Convert HTML content to plain text"""
    soup = BeautifulSoup(html_content, 'html.parser')
    return soup.get_text()

def clean_body(body):
    """Clean the email body by removing extraneous information."""
    # Remove email addresses
    body = re.sub(r'[\w\.-]+@[\w\.-]+', '', body)
    # Remove HTML tags
    body = re.sub(r'<[^>]+>', '', body)
    # Remove extra white spaces, newlines, and special characters
    body = re.sub(r'\s+', ' ', body).strip()
    return body

if __name__ == '__main__':
    app.run('localhost', 5000, debug=True)