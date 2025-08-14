import os
from dotenv import load_dotenv

load_dotenv()

TG_BOT_TOKEN = os.getenv("TG_BOT_TOKEN")
GMAIL_CLIENT_SECRET_FILE = os.getenv("GMAIL_CLIENT_SECRET_FILE", "./gmail_client_secret.json")
GMAIL_CREDENTIALS_FILE = os.getenv("GMAIL_CREDENTIALS_FILE", "./gmail_credentials.json")
DB_PATH = os.getenv("DB_PATH", "bot.db")
CHAT_ID = os.getenv("CHAT_ID")
YAHOO_EMAIL = os.getenv("YAHOO_EMAIL")
YAHOO_APP_PASSWORD = os.getenv("YAHOO_APP_PASSWORD")  # App password, not regular password
OPENAI_API_KEY = os.getenv("OPENAI_API_KEY")

GMAIL_ACCOUNTS = [
    {
        "name": "alfacommunicationdesign@gmail.com",
        "credentials": "gmail_credentials.json"
    },
    {
        "name": "alfavvidandneiro@gmail.com",
        "credentials": "gmail_credentials_alfavvidandneiro.json"
    },
    {
        "name": "alfamarketingdepartment2022@gmail.com",
        "credentials": "gmail_credentials_alfamarketingdepartment2022.json"
    }
]