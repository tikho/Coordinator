import base64 
import imaplib, email, re
from googleapiclient.discovery import build
from googleapiclient.errors import HttpError
from google_auth_oauthlib.flow import InstalledAppFlow
from google.auth.transport.requests import Request
import os
import pickle
import logging
from datetime import datetime, timedelta
import pytz

from config import TG_BOT_TOKEN, GMAIL_CLIENT_SECRET_FILE, GMAIL_CREDENTIALS_FILE


CODE_REGEX = re.compile(r"\b\d{6}\b")

# Список одобренных компаний (от которых будем проверять коды)
APPROVED_COMPANIES = ["google.com", "openai.com"]

# Функция для получения основного домена из email (игнорируем поддомены)
def get_main_domain_from_email(email: str):
    """Извлекаем основной домен из email, игнорируя поддомены и символ >"""
    domain = email.split('@')[-1]
    # Удаляем символ ">" в конце, если он есть
    domain = domain.rstrip('>')  # Убираем символ ">"
    # Извлекаем основной домен из возможных поддоменов
    main_domain = ".".join(domain.split('.')[-2:])  # Берем последние два сегмента (например, openai.com, google.com)
    return main_domain

def parse_code_from_email(body: str):
    match = CODE_REGEX.search(body)
    if match:
        code = match.group(0)
        # Проверяем, не является ли код из списка игнорируемых
        return code
    return None

def mark_message_as_read(service, message_id):
    """Отмечаем письмо как прочитанное"""
    message = service.users().messages().modify(
        userId="me", id=message_id,
        body={"removeLabelIds": ["UNREAD"]}
    ).execute()
    print(f"Message with ID: {message_id} marked as read.")


# Gmail API Authentication
def authenticate_gmail():
    SCOPES = ['https://www.googleapis.com/auth/gmail.readonly', 'https://www.googleapis.com/auth/gmail.modify']
    creds = None
    if os.path.exists(GMAIL_CREDENTIALS_FILE):
        logging.info("authenticating gmail with " + GMAIL_CREDENTIALS_FILE)
        with open(GMAIL_CREDENTIALS_FILE, 'rb') as token:
            creds = pickle.load(token)
            logging.info(creds)

    if not creds or not creds.valid:
        if creds and creds.expired and creds.refresh_token:
            creds.refresh(Request())
        else:
            logging.info("authenticating gmail with" + GMAIL_CLIENT_SECRET_FILE)
            flow = InstalledAppFlow.from_client_secrets_file(
                GMAIL_CLIENT_SECRET_FILE, SCOPES)
            creds = flow.run_local_server(port=8080)
        with open(GMAIL_CREDENTIALS_FILE, 'wb') as token:
            pickle.dump(creds, token)

    service = build('gmail', 'v1', credentials=creds)
    logging.info("authenticated gmail")
    return service



def check_gmail_mail():
    logging.info("checking gmail")
    service = authenticate_gmail()
    results = []

    # Используем q="newer_than:1d is:unread" для фильтрации по письмам за последний день, которые не прочитаны
    query = "newer_than:1d is:unread"

    try:
        # Получаем письма за последний день
        messages = service.users().messages().list(userId='me', labelIds=['INBOX'], q=query).execute()
    except HttpError as error:
        print(f"An error occurred: {error}")
        return results

    if 'messages' in messages:
        for msg in messages['messages']:
            msg_data = service.users().messages().get(userId='me', id=msg['id']).execute()
            for part in msg_data['payload']['headers']:
                if part['name'] == 'From':
                    from_email = part['value']
            body = ""
            timestamp = msg_data['internalDate']  # Время получения письма

            # Извлекаем заголовки письма
            for part in msg_data['payload']['headers']:
                if part['name'] == 'From':
                    from_email = part['value']
                if part['name'] == 'To':
                    to_email = part['value']
            
            # Получаем основной домен из email отправителя
            domain = get_main_domain_from_email(from_email)

            # logging.info('checked mail from ' + domain)

            # Проверяем, что домен есть в списке одобренных компаний
            if domain not in APPROVED_COMPANIES:
                continue  # Пропускаем письма от неподтвержденных компаний

            # Если есть 'parts', то извлекаем из них тело письма
            if 'parts' in msg_data['payload']:
                for part in msg_data['payload']['parts']:
                    if part['mimeType'] == 'text/plain':
                        body = part['body']['data']
                        body = base64.urlsafe_b64decode(body).decode("utf-8")
            # Если 'parts' нет, проверяем наличие 'body'
            elif 'body' in msg_data['payload']:
                body = msg_data['payload']['body']['data']
                body = base64.urlsafe_b64decode(body).decode("utf-8")

            # Ищем код в теле письма
            code = parse_code_from_email(body)
            if code:

                # Преобразуем время из timestamp в читаемый формат (Московское время)
                timestamp = int(timestamp) / 1000  # Переводим в секунды
                utc_time = datetime.utcfromtimestamp(timestamp)  # Время в UTC
                moscow_time = utc_time.astimezone(pytz.timezone('Europe/Moscow'))  # Переводим в московский часовой пояс
                time_received = moscow_time.strftime('%Y-%m-%d %H:%M:%S')

                logging.info(to_email + ' got code: ' + code + ' from email: ' + domain + ' at ' + time_received)
                results.append((to_email, domain, time_received, code))

                # Отметить письмо как прочитанное, если найден код
                mark_message_as_read(service, msg['id'])


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
