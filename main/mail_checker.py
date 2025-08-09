import imaplib, email, re
from googleapiclient.discovery import build
from google_auth_oauthlib.flow import InstalledAppFlow
from google.auth.transport.requests import Request
import os
import pickle

CODE_REGEX = re.compile(r"\b\d{4,8}\b")

def parse_code_from_email(body: str):
    match = CODE_REGEX.search(body)
    return match.group(0) if match else None

# Gmail API Authentication
def authenticate_gmail():
    SCOPES = ['https://www.googleapis.com/auth/gmail.readonly']
    creds = None
    if os.path.exists('gmail_credentials.json'):
        with open('gmail_credentials.json', 'rb') as token:
            creds = pickle.load(token)

    if not creds or not creds.valid:
        if creds and creds.expired and creds.refresh_token:
            creds.refresh(Request())
        else:
            flow = InstalledAppFlow.from_client_secrets_file(
                'gmail_client_secret.json', SCOPES)
            creds = flow.run_local_server(port=0)
        with open('gmail_credentials.json', 'wb') as token:
            pickle.dump(creds, token)

    service = build('gmail', 'v1', credentials=creds)
    return service

def check_gmail_mail():
    service = authenticate_gmail()
    results = []
    messages = service.users().messages().list(userId='me', labelIds=['INBOX'], q="is:unread").execute()
    if 'messages' in messages:
        for msg in messages['messages']:
            msg_data = service.users().messages().get(userId='me', id=msg['id']).execute()
            for part in msg_data['payload']['headers']:
                if part['name'] == 'From':
                    from_email = part['value']
            body = ""
            for part in msg_data['payload']['parts']:
                if part['mimeType'] == 'text/plain':
                    body = part['body']['data']
                    body = base64.urlsafe_b64decode(body).decode("utf-8")
            code = parse_code_from_email(body)
            if code:
                results.append((from_email, msg_data['snippet'], code))
    return results

# Yahoo Mail IMAP Authentication
def check_yahoo_mail(user, password):
    mail = imaplib.IMAP4_SSL("imap.mail.yahoo.com")
    mail.login(user, password)
    mail.select("inbox")
    status, data = mail.search(None, 'UNSEEN')
    ids = data[0].split()
    results = []
    for mail_id in ids:
        status, msg_data = mail.fetch(mail_id, "(RFC822)")
        for response_part in msg_data:
            if isinstance(response_part, tuple):
                msg = email.message_from_bytes(response_part[1])
                body = ""
                if msg.is_multipart():
                    for part in msg.walk():
                        if part.get_content_type() == "text/plain":
                            body += part.get_payload(decode=True).decode()
                else:
                    body = msg.get_payload(decode=True).decode()
                code = parse_code_from_email(body)
                if code:
                    results.append((msg["From"], msg["Subject"], code))
    return results
