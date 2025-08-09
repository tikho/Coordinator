from aiogram import Bot, Dispatcher, types
from aiogram.utils import executor
import logging
import asyncio
from .config import TG_BOT_TOKEN
from .mail_checker import check_gmail_mail, check_yahoo_mail

logging.basicConfig(level=logging.INFO)

bot = Bot(token=TG_BOT_TOKEN)
dp = Dispatcher(bot)

@dp.message_handler(commands=['start'])
async def start_cmd(message: types.Message):
    await message.answer("Привет! Я буду присылать коды доступа с твоих почт. Используй /add_mail для добавления.")

@dp.message_handler(commands=['add_mail'])
async def add_mail_cmd(message: types.Message):
    # Заглушка для добавления почты
    await message.answer("Добавь почту и пароль через команду /add_mail <email> <password>")

async def check_mails():
    while True:
        # Пример проверки почты
        gmail_results = check_gmail_mail()
        yahoo_results = check_yahoo_mail('your_yahoo_email', 'your_password')

        # Тут будет логика отправки сообщений в чат с кодами
        for result in gmail_results + yahoo_results:
            from_email, subject, code = result
            await bot.send_message(chat_id="your_chat_id", text=f"Код: {code} от {from_email}. Тема: {subject}")

        await asyncio.sleep(60)  # Пауза между проверками

async def on_startup(dp):
    logging.info("Bot started")
    asyncio.create_task(check_mails())  # Запускаем асинхронную проверку почты

if __name__ == '__main__':
    from aiogram import executor
    executor.start_polling(dp, skip_updates=True, on_startup=on_startup)
