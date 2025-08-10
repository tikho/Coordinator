from google_auth_oauthlib.flow import InstalledAppFlow
import pickle

# Устанавливаем необходимые области доступа
SCOPES = ['https://www.googleapis.com/auth/gmail.readonly']

# Инициализация потока OAuth
flow = InstalledAppFlow.from_client_secrets_file(
    'gmail_client_secret.json', SCOPES)
creds = flow.run_local_server(port=8080)

# Сохранение полученных учетных данных в файл
with open('gmail_credentials.json', 'wb') as token:
    pickle.dump(creds, token)

print("Токены успешно сохранены в 'gmail_credentials.json'")