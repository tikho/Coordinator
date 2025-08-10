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
from urllib.parse import urlparse
from typing import Optional, Tuple


from config import TG_BOT_TOKEN, GMAIL_CLIENT_SECRET_FILE, GMAIL_CREDENTIALS_FILE


CODE_REGEX = re.compile(r"\b\d{6,8}\b")

# Список одобренных компаний (от которых будем проверять коды)
APPROVED_COMPANIES = ["google.com", "openai.com", "yahoo.com", "dropbox.com","anthropic.com", "magnific.ai", "figma.com", "runpod.io"]

A_TAG_REGEX = re.compile(r'<a\s+[^>]*href=["\']([^"\']+)["\'][^>]*>(.*?)</a>', re.IGNORECASE|re.DOTALL)
SIGNIN_ANCHOR_RE = re.compile(r"sign\s*in\s*to\s+(.+)", re.IGNORECASE)
URL_REGEX = re.compile(r"https?://[^\s<>\]\)\"']+", re.IGNORECASE)

def etld_plus_one(domain: str) -> str:
    domain = (domain or "").rstrip(">").lower()
    parts = domain.split(".")
    return ".".join(parts[-2:]) if len(parts) >= 2 else domain

def find_signin_link_in_html(html_text: str) -> Optional[Tuple[str, str]]:
    """Ищем <a ...>...</a>, где внутренний текст содержит Sign in to ... Возвращаем (service_name, url)."""
    if not html_text:
        return None
    for href, inner in A_TAG_REGEX.findall(html_text):
        # чистим внутренний текст от тегов, ужимаем пробелы
        inner_text = re.sub("<.*?>", "", inner)
        inner_text = " ".join(inner_text.split())
        m = SIGNIN_ANCHOR_RE.search(inner_text)
        if not m:
            continue
        service = m.group(1).strip().strip(".:!- ")
        if not href.lower().startswith("http"):
            continue
        host = etld_plus_one(urlparse(href).netloc)
        if host in APPROVED_COMPANIES:
            return (service, href)
    return None

def find_signin_link_in_text(plain_text: str) -> Optional[Tuple[str, str]]:
    """В plain тексте ищем Sign in to X и первый URL в пределах 200 символов справа от фразы."""
    if not plain_text:
        return None
    for m in SIGNIN_ANCHOR_RE.finditer(plain_text):
        service = m.group(1).strip().strip(".:!- ")
        window = plain_text[m.end(): m.end()+200]
        u = URL_REGEX.search(window)
        if not u:
            continue
        url = u.group(0)
        host = etld_plus_one(urlparse(url).netloc)
        if host in APPROVED_COMPANIES:
            return (service, url)
    return None


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
        resp = service.users().messages().list(
            userId='me', labelIds=['INBOX'], q=query
        ).execute()
    except HttpError as error:
        logging.error("Gmail list error: %s", error)
        return results

    if 'messages' not in resp:
        return results

    def b64_to_text(b64):
        try:
            return base64.urlsafe_b64decode(b64.encode()).decode("utf-8", errors="ignore")
        except Exception:
            return ""

    # Рекурсивный сборщик text/plain и text/html
    def collect_bodies(payload):
        text_body, html_body = "", ""
        if not payload:
            return text_body, html_body

        mime = payload.get("mimeType", "")
        body = payload.get("body", {})
        data = body.get("data")

        if mime.startswith("text/plain") and data:
            text_body += b64_to_text(data)
        elif mime.startswith("text/html") and data:
            html_body += b64_to_text(data)

        parts = payload.get("parts") or []
        for p in parts:
            t, h = collect_bodies(p)
            text_body += t
            html_body += h
        return text_body, html_body

    for msg in resp['messages']:
        msg_id = msg['id']
        m = service.users().messages().get(userId='me', id=msg_id).execute()
        payload = m.get('payload', {})
        headers = payload.get('headers', [])
        from_email = next((h['value'] for h in headers if h['name'] == 'From'), "")
        to_email   = next((h['value'] for h in headers if h['name'] == 'To'), "")
        internal_ts = int(m.get('internalDate', "0")) // 1000

        # Белый список по eTLD+1 отправителя
        domain = get_main_domain_from_email(from_email)
        if domain not in APPROVED_COMPANIES:
            continue

        # Достаём и текст, и HTML
        text_body, html_body = collect_bodies(payload)
        if not text_body and not html_body:
            # бывает "single-part" без parts
            bdata = payload.get('body', {}).get('data')
            if bdata:
                text_body = b64_to_text(bdata)

        # 1) пытаемся вытащить код (из текста и "очищенного" HTML)
        code = parse_code_from_email(text_body)
        if not code and html_body:
            html_stripped = re.sub("<.*?>", " ", html_body)
            code = parse_code_from_email(html_stripped)

        # 2) если кода нет — пробуем найти sign-in ссылку по правилу "Sign in to ..."
        service_name = None
        signin_url = None
        if not code:
            hit = find_signin_link_in_html(html_body) or find_signin_link_in_text(text_body)
            if hit:
                service_name, signin_url = hit

        # если ничего не нашли — к следующему письму
        if not code and not signin_url:
            continue

        # готовим время (МСК)
        dt = datetime.utcfromtimestamp(internal_ts).astimezone(pytz.timezone('Europe/Moscow'))
        time_received = dt.strftime('%Y-%m-%d %H:%M:%S')

        # 4‑я строка сообщения: либо код, либо кликабельная ссылка
        if code:
            payload_html = f"<code>{html.escape(code)}</code>"
        else:
            safe_service = html.escape(service_name or "Service")
            safe_url = html.escape(signin_url)
            payload_html = f"<a href=\"{safe_url}\">Sign in to {safe_service}</a>"

        # добавляем результат в формате, который удобно склеить на стороне main.py
        results.append((to_email, domain, time_received, payload_html))

        # помечаем прочитанным, чтобы не дублировать
        try:
            mark_message_as_read(service, msg_id)
        except HttpError as e:
            logging.warning("mark read failed for %s: %s", msg_id, e)

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
