import os

TG_BOT_TOKEN = os.getenv("TG_BOT_TOKEN")
GMAIL_CLIENT_SECRET_FILE = os.getenv("GMAIL_CLIENT_SECRET_FILE", "../gmail_client_secret.json")
GMAIL_CREDENTIALS_FILE = os.getenv("GMAIL_CREDENTIALS_FILE", "../gmail_credentials.json")
DB_PATH = os.getenv("DB_PATH", "bot.db")
