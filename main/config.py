import os
from dotenv import load_dotenv

load_dotenv()

TG_BOT_TOKEN = os.getenv("TG_BOT_TOKEN")
GMAIL_CLIENT_SECRET_FILE = os.getenv("GMAIL_CLIENT_SECRET_FILE", "./gmail_client_secret.json")
GMAIL_CREDENTIALS_FILE = os.getenv("GMAIL_CREDENTIALS_FILE", "./gmail_credentials.json")
DB_PATH = os.getenv("DB_PATH", "bot.db")
CHAT_ID = os.getenv("CHAT_ID")