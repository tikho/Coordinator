import base64 
import imaplib, email, re, html
from googleapiclient.discovery import build
from googleapiclient.errors import HttpError
from google_auth_oauthlib.flow import InstalledAppFlow
from google.auth.transport.requests import Request
from google.auth.exceptions import RefreshError
from google.oauth2.credentials import Credentials
import os
import pickle
import logging
from datetime import datetime, timedelta
import pytz
import quopri
from urllib.parse import urlparse, unquote
from typing import Optional, Tuple
import json, os, time
import requests
from config import OPENAI_API_KEY
import mailparser

from config import (
    TG_BOT_TOKEN, 
    GMAIL_CLIENT_SECRET_FILE, 
    GMAIL_CREDENTIALS_FILE,
    YAHOO_EMAIL,
    YAHOO_APP_PASSWORD,
    GMAIL_ACCOUNTS
)

# comment5 to test deploy

# simple 6–8 digit codes
CODE_REGEX = re.compile(r"\b\d{4,8}\b")
# gate words
CODE_WORD_RE = re.compile(r"\b(code|код|кодом|местоположения)\b", re.IGNORECASE)
SIGNIN_PRESENT_RE = re.compile(r"sign[\s\u00A0]*in[\s\u00A0]", re.IGNORECASE)

# Регулярное выражение для поиска фразы "Подтвердить вход"
SIGNIN_ANCHOR_RE = re.compile(r"подтвердить\s*вход", re.IGNORECASE)

# Регулярное выражение для поиска всех ссылок <a href="...">
A_TAG_REGEX = re.compile(r'<a\s+[^>]*href=["\']([^"\']+)["\'][^>]*>(.*?)</a>', re.IGNORECASE|re.DOTALL)

# Функция для декодирования текста, если он закодирован в quoted-printable
def decode_quoted_printable(text):
    return quopri.decodestring(text).decode('utf-8', errors='ignore')

# Список одобренных компаний (от которых будем проверять коды)
APPROVED_COMPANIES = [
    "google.com",
    "openai.com",
    "yahoo.com",
    "dropbox.com",
    "anthropic.com",
    "magnific.ai",
    "pstmrk.it",
    "figma.com",
    "runpod.io",
    "timeweb.cloud",
    "recraft.ai",
    "opencreator.io",
    "midjourney.com",
    "discord.com",
    "atlassian.com",
    "gptunnel.ru"
]


# Функция для получения основного домена из email (игнорируем поддомены)
def get_main_domain_from_email(email: str):
    """Извлекаем основной домен из email, игнорируя поддомены и символ >"""
    domain = email.split('@')[-1]
    # Удаляем символ ">" в конце, если он есть
    domain = domain.rstrip('>')  # Убираем символ ">"
    # Извлекаем основной домен из возможных поддоменов
    main_domain = ".".join(domain.split('.')[-2:])  # Берем последние два сегмента (например, openai.com, google.com)
    return main_domain

def mark_message_as_read(gmail, message_id):
    """Отмечаем письмо как прочитанное"""
    gmail.users().messages().modify(
        userId="me", id=message_id,
        body={"removeLabelIds": ["UNREAD"]}
    ).execute()
    print(f"Message with ID: {message_id} marked as read.")


def check_all_gmail_accounts():
    all_results = []
    for acc in GMAIL_ACCOUNTS:
        results = check_gmail_mail(credentials_file=acc["credentials"])
        logging.info("checked gmail: " + acc["name"] + " with results:")
        logging.info("Items: %r", results) 
        all_results.extend(results)
    return all_results
    

# Gmail API Authentication
def authenticate_gmail(credentials_file):
    SCOPES = [
        'https://www.googleapis.com/auth/gmail.readonly',
        'https://www.googleapis.com/auth/gmail.modify'
    ]
    creds = None

    # Если файл с токенами существует, загружаем данные
    if os.path.exists(credentials_file):
        logging.info("Authenticating Gmail with " + credentials_file)
        with open(credentials_file, 'rb') as token:
            creds = pickle.load(token)
        
    # Проверяем refresh token
    if creds and creds.refresh_token:
        logging.info(f"Refresh token сохранён: {creds.refresh_token}")
    else:
        logging.info("Refresh token не найден.")

    # Если токен не существует или он недействителен, создаём новый
    if not creds or not creds.valid:
        if creds and creds.expired and creds.refresh_token:
            # Если refresh token есть и он действителен, обновляем access token
            creds.refresh(Request())
        else:
            # Запускаем процесс авторизации и получаем новые credentials (включая refresh token)
            flow = InstalledAppFlow.from_client_secrets_file(
                'gmail_client_secret.json', SCOPES
            )
            creds = flow.run_local_server(port=8080, access_type='offline')
        
        # Сохраняем обновленные credentials, включая refresh token
        with open(credentials_file, 'wb') as token:
            pickle.dump(creds, token)

    if not creds:
        logging.error("Не удалось аутентифицировать пользователя.")
        return []


    logging.info("authenticated with: " + credentials_file)
    return build('gmail', 'v1', credentials=creds, cache_discovery=False)


def check_gmail_mail(credentials_file):
    gmail = authenticate_gmail(credentials_file)
    results = []

    # Используем q="newer_than:1d is:unread" для фильтрации по письмам за последний день, которые не прочитаны
    query = "newer_than:1d is:unread"

    try:
        # Получаем письма за последний день
        resp = gmail.users().messages().list(
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
        # fetch raw + parse
        m = gmail.users().messages().get(userId='me', id=msg_id, format='raw').execute()
        raw_b64 = m.get('raw', '')
        raw_bytes = base64.urlsafe_b64decode(raw_b64.encode())

        plain, html_body, links, from_email, to_email, date_dt = parse_email_with_mailparser(raw_bytes)

        # whitelist by sender domain
        domain = get_main_domain_from_email(from_email)
        # logging.info("domain: " + domain)
        if domain not in APPROVED_COMPANIES:
            continue

        # time_received from letter date, fallback to internalDate
        internal_ts = int(m.get('internalDate', "0")) // 1000
        if date_dt:
            if date_dt.tzinfo is None:
                date_dt = date_dt.replace(tzinfo=pytz.UTC)
            time_received = date_dt.astimezone(pytz.timezone('Europe/Moscow')).strftime('%Y-%m-%d %H:%M:%S')
        else:
            dt = datetime.utcfromtimestamp(internal_ts).astimezone(pytz.timezone('Europe/Moscow'))
            time_received = dt.strftime('%Y-%m-%d %H:%M:%S')

        # build anchors-only for AI
        anchors = "\n".join(f'<a href="{u}">{u}</a>' for u in links)

        # Build human-visible plain text
        plain = plain if 'plain' in locals() and plain else (text_body or (html_to_visible_text(html_body) if html_body else ""))

        code = None
        signin_url = None
        service_label = None

        # 1) Only check for code if the letter mentions "code" or "код" or "подтвердите вход"
        if CODE_WORD_RE.search(plain):
            logging.info("found mail")
            code = extract_code_smart(plain)

        # 2) Only check for link if the letter mentions "sign in to"
        if not code and SIGNIN_PRESENT_RE.search(plain) or SIGNIN_ANCHOR_RE.search(plain):
            hit = find_signin_link_if_present(html_body, plain)
            if hit:
                service_label, signin_url = hit

        # Skip if still nothing
        if not code and not signin_url:
            continue

        # Payload
        if code:
            payload_html = f"<code>{html.escape(code)}</code>"
        else:
            # if service_label and service_label.lower() in ("pstmrk.it", "Подтвердить вход"):
            #     service_label = domain
            # safe_service = html.escape(service_label or "Service")
            safe_service = domain
            safe_url = html.escape(signin_url)
            payload_html = f"<a href=\"{safe_url}\">Sign in to {safe_service}</a>"

        # добавляем результат в формате, который удобно склеить на стороне main.py
        results.append((to_email, domain, time_received, payload_html))

        # помечаем прочитанным, чтобы не дублировать
        try:
            mark_message_as_read(gmail, msg_id)
        except HttpError as e:
            logging.warning("mark read failed for %s: %s", msg_id, e)

    return results


# Yahoo Mail IMAP Authentication
def check_yahoo_mail():
    """Check Yahoo Mail for new messages using IMAP."""
    logging.info("checking yahoo mail")
    if not YAHOO_EMAIL or not YAHOO_APP_PASSWORD:
        logging.warning("Yahoo Mail credentials not configured")
        return []

    results = []
    try:
        mail = imaplib.IMAP4_SSL("imap.mail.yahoo.com")
        mail.login(YAHOO_EMAIL, YAHOO_APP_PASSWORD)
        mail.select("inbox")  # read-write
        
        # Search for unread messages from the last 24 hours
        date = (datetime.now() - timedelta(days=1)).strftime("%d-%b-%Y")
        status, data = mail.search(None, f'(UNSEEN SINCE {date})')
        
        if status != 'OK':
            logging.error("Failed to search Yahoo Mail")
            return results

        for num in data[0].split():
            status, msg_data = mail.fetch(num, '(BODY.PEEK[])')  # avoid auto \Seen on fetch
            if status != 'OK':
                continue

            # After fetching RFC822 (BODY.PEEK[])
            email_body = msg_data[0][1]  # raw RFC822 bytes
            plain, html_body, links, from_email, to_email, date_dt = parse_email_with_mailparser(email_body)

            # Domain whitelist
            domain = get_main_domain_from_email(from_email)
            if domain not in APPROVED_COMPANIES:
                continue

            # Time received
            if date_dt:
                if date_dt.tzinfo is None:
                    date_dt = date_dt.replace(tzinfo=pytz.UTC)
                time_received = date_dt.astimezone(pytz.timezone('Europe/Moscow')).strftime('%Y-%m-%d %H:%M:%S')
            else:
                time_received = datetime.now(pytz.timezone('Europe/Moscow')).strftime('%Y-%m-%d %H:%M:%S')

            # Derive human-visible plain text (Yahoo is often HTML-only)
            plain = plain if 'plain' in locals() and plain else html_to_visible_text(html_body)

            code = None
            signin_url = None
            service_label = None

            # 1) Only check for code if the letter mentions "code" or "код"
            if CODE_WORD_RE.search(plain):
                code = extract_code_smart(plain)

            # 2) Only check for link if the letter mentions "sign in to"
            if not code and SIGNIN_PRESENT_RE.search(plain):
                hit = find_signin_link_if_present(html_body, plain)
                if hit:
                    service_label, signin_url = hit

            # Skip if still nothing
            if not code and not signin_url:
                continue

            # Payload
            if code:
                payload_html = f"<code>{html.escape(code)}</code>"
            else:
                if service_label and service_label.lower() == "pstmrk.it":
                    service_label = domain
                safe_service = html.escape(service_label or "Service")
                safe_url = html.escape(signin_url)
                payload_html = f"<a href=\"{safe_url}\">Sign in to {safe_service}</a>"

            # Add to results
            results.append((to_email, domain, time_received, payload_html))

            # Explicitly mark as read only for processed messages
            try:
                mail.store(num, '+FLAGS', '\\Seen')
                logging.info("Yahoo: marked message %s as read", num.decode() if isinstance(num, bytes) else str(num))
            except Exception as e:
                logging.warning("Yahoo: failed to mark %s as read: %s", num, e)

        mail.logout()
    except Exception as e:
        logging.error(f"Error checking Yahoo Mail: {str(e)}")
        return results

    return results

def html_to_visible_text(html_body: str) -> str:
    if not html_body:
        return ""
    # Remove scripts/styles
    html_clean = re.sub(r"<script[\s\S]*?</script>", " ", html_body, flags=re.IGNORECASE)
    html_clean = re.sub(r"<style[\s\S]*?</style>", " ", html_clean, flags=re.IGNORECASE)
    # Line breaks for common block boundaries
    html_clean = re.sub(r"(?i)<br\s*/?>", "\n", html_clean)
    html_clean = re.sub(r"(?i)</(p|div|li|tr|h[1-6])>", "\n", html_clean)
    # Strip tags
    text = re.sub(r"<.*?>", " ", html_clean)
    # Unescape HTML entities and normalize spaces
    text = html.unescape(text).replace("\u00A0", " ")
    text = re.sub(r"[ \t]+", " ", text)
    text = re.sub(r"\n\s*\n+", "\n", text)
    return text.strip()

def extract_code_smart(plain: str) -> Optional[str]:
    if not plain:
        return None
    # find all candidates
    candidates = [(m.group(0), m.start(), m.end()) for m in CODE_REGEX.finditer(plain)]
    
    # filter out repeated-digit codes like 000000, 111111, etc.
    def is_repeated(s: str) -> bool:
        return len(set(s)) == 1
    candidates = [c for c in candidates if not is_repeated(c[0])]
    if not candidates:
        return None

    # find positions of the keyword "code/код"
    kw_spans = [m.span() for m in CODE_WORD_RE.finditer(plain)]
    if not kw_spans:
        # fallback: pick the longest (prefer 7-8) then earliest
        candidates.sort(key=lambda x: (-len(x[0]), x[1]))
        return candidates[0][0]

    # score by min distance to any keyword occurrence, prefer longer codes
    def score(c):
        _, s, e = c
        center = (s + e) // 2
        dist = min(abs(center - ((ks + ke) // 2)) for ks, ke in kw_spans)
        # shorter distance better, longer code better
        return (dist, -len(c[0]), s)
    candidates.sort(key=score)
    return candidates[0][0] if candidates else None

QP_A_HREF_RE = re.compile(r"<a\b[^>]*?\bhref\s*=\s*(?:=3D)?(['\"])(.+?)\1", re.IGNORECASE | re.DOTALL)
EMBEDDED_URL_RE = re.compile(r"https?://[^\s\"'>]+", re.IGNORECASE)

def extract_first_qp_href(html_body: str) -> Optional[str]:
    if not html_body:
        return None
    # normalize quoted‑printable soft breaks and '=3D'
    s = html_body.replace("=\r\n", "").replace("=\n", "").replace("=3D", "=")
    # unescape HTML entities
    s = html.unescape(s)
    # find first <a ... href=3D'...'> or "..."
    m = QP_A_HREF_RE.search(s)
    if not m:
        return None
    raw = m.group(2)
    # decode percent-encoding once or twice; also try to pull embedded https URL
    dec1 = unquote(raw)
    dec2 = unquote(dec1)
    u = EMBEDDED_URL_RE.search(dec2) or EMBEDDED_URL_RE.search(dec1) or EMBEDDED_URL_RE.search(raw)
    return u.group(0) if u else None

def find_signin_link_if_present(html_body: str, plain_text: str) -> Optional[Tuple[str, str]]:
    # If the letter mentions "Sign in to ..." anywhere, take first href from HTML
    has_phrase = False
    logging.info("checking for sign in link")
    if plain_text and SIGNIN_PRESENT_RE.search(plain_text):
        has_phrase = True
    if not has_phrase and html_body:
        stripped = re.sub(r"<.*?>", " ", html_body)
        stripped = html.unescape(stripped).replace("\u00A0", " ")
        stripped = " ".join(stripped.split())
        has_phrase = bool(SIGNIN_PRESENT_RE.search(stripped))
    if not has_phrase:
        # logging.info("html_body: " + html_body)
        for href, inner in A_TAG_REGEX.findall(html_body):
            # inner_text = decode_quoted_printable(inner)
            inner_text = re.sub("<.*?>", "", inner)  # Убираем все HTML-теги
            inner_text = " ".join(inner_text.split())  # Убираем лишние пробелы
            if SIGNIN_ANCHOR_RE.search(inner_text):  # Проверяем на фразу "Подтвердить вход"
                return (inner_text, href)
        return None
        

    href = extract_first_qp_href(html_body or "")
    if not href or not href.lower().startswith(("http://", "https://")):
        return None

    host = urlparse(href).netloc.lower()
    host = ".".join(host.split(".")[-2:])

    if host not in APPROVED_COMPANIES:
        return None
    return (host, href)

P_TAG_RE = re.compile(r"(?is)<p\b[^>]*>.*?</p>")
A_TAG_WITH_HREF_RE = re.compile(r"(?is)<a\b[^>]*?\bhref\s*=\s*(?:=3D)?(['\"])(.+?)\1[^>]*>.*?</a>")

def extract_p_and_a_html(html_body: str) -> str:
    if not html_body:
        return ""
    # normalize quoted‑printable artifacts and entities once
    s = html_body.replace("=\r\n", "").replace("=\n", "").replace("=3D", "=")
    s = html.unescape(s)
    parts = []
    parts.extend(P_TAG_RE.findall(s))
    parts.extend(A_TAG_WITH_HREF_RE.findall(s) and [m.group(0) for m in A_TAG_WITH_HREF_RE.finditer(s)] or [])
    return "\n".join(parts)

def visible_text_from_p_only(html_body: str) -> str:
    # Use only <p> blocks for plain text if no text/plain
    if not html_body:
        return ""
    s = html_body.replace("=\r\n", "").replace("=\n", "").replace("=3D", "=")
    s = html.unescape(s)
    p_blocks = P_TAG_RE.findall(s)
    if not p_blocks:
        return ""
    text = " ".join(re.sub(r"<.*?>", " ", b) for b in p_blocks)
    text = re.sub(r"[ \t]+", " ", text)
    text = re.sub(r"\n\s*\n+", "\n", text)
    return text.strip()

# Extract only visible text and only <a> links

QP_A_HREF_FULL_RE = re.compile(r'(?is)<a\b[^>]*?\bhref\s*=\s*(?:=3D)?([\'"])(.+?)\1[^>]*>(.*?)</a>')

def extract_links_as_anchors(html_body: str) -> str:
    if not html_body:
        return ""
    s = html_body.replace("=\r\n", "").replace("=\n", "").replace("=3D", "=")
    s = html.unescape(s)
    anchors = []
    for m in QP_A_HREF_FULL_RE.finditer(s):
        raw_href = m.group(2)
        inner = m.group(3) or ""
        # normalize href
        dec1 = unquote(raw_href)
        dec2 = unquote(dec1)
        href = dec2 or dec1 or raw_href
        # visible text
        text = html.unescape(re.sub(r"<.*?>", " ", inner)).strip()
        text = re.sub(r"\s+", " ", text)
        if href and href.lower().startswith(("http://", "https://")):
            anchors.append(f'<a href="{href}">{text}</a>')
    return "\n".join(anchors)

def parse_email_with_mailparser(raw_bytes: bytes) -> tuple[str, str, list[str], str, str, Optional[datetime]]:
    mp = mailparser.parse_from_bytes(raw_bytes)

    text_parts = [t for t in (mp.text_plain or []) if t]
    plain_text = "\n".join(text_parts).strip()

    html_parts = [h for h in (mp.text_html or []) if h]
    html_body = "\n".join(html_parts).strip()

    if not plain_text and html_body:
        plain_text = html_to_visible_text(html_body)

    links = mp.urls or []

    from_email = (mp.from_[0][1] if mp.from_ else "")  # (name, email)
    to_email = (mp.to[0][1] if mp.to else "")
    date_dt = mp.date  # datetime or None

    return plain_text, html_body, links, from_email, to_email, date_dt
