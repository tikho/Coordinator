from aiogram import Bot, Dispatcher, types
import logging
import asyncio
from mail_checker import check_gmail_mail, check_yahoo_mail
from aiogram.types import Message
from aiogram.filters import Command
from aiogram.types import ReplyKeyboardRemove
import re
import html

from config import TG_BOT_TOKEN, CHAT_ID

logging.basicConfig(level=logging.INFO)

# Инициализация бота и диспетчера
bot = Bot(token=TG_BOT_TOKEN)
dp = Dispatcher(bot=bot)

@dp.message(Command("start"))
async def start_cmd(message: Message):
    """Обработчик для команды /start"""
    await message.answer("Привет! Я буду присылать коды доступа с твоих почт. Используй /add_mail для добавления.")

@dp.message(Command("add_mail"))
async def add_mail_cmd(message: Message):
    """Обработчик для команды /add_mail"""
    await message.answer("Добавь почту и пароль через команду /add_mail <email> <password>")

# === Фоновая задача ===
async def check_mails_task(bot: Bot, chat_id: int):
    """
    Периодически проверяет входящие и шлёт коды в указанный чат/канал.
    Важно: check_gmail_mail / check_yahoo_mail синхронные → гоняем в thread-пуле.
    """
    while True:
        try:

            gmail_results = check_gmail_mail()
            # yahoo_results = check_yahoo_mail('your_yahoo_email', 'your_password')

            # Логика отправки сообщений в чат с кодами
            # for result in gmail_results + yahoo_results:
            for result in gmail_results:
                to_email, company_domain, time_received, code = result
                logging.info('sending message')

                # escaped_company_domain = company_domain.replace('.', r'\.')  # Экранируем все точки
                # escaped_to_email = to_email.replace('.', r'\.')

                to_email = gpt_markdown_to_telegram_html(to_email)
                company_domain = gpt_markdown_to_telegram_html(company_domain)
                time_received = gpt_markdown_to_telegram_html(time_received)
                code = gpt_markdown_to_telegram_html(code)

                await bot.send_message(
                    chat_id=chat_id, 
                    text=(
                        f"{to_email}\n"
                        f"{company_domain} {time_received}\n"
                        f"\n"
                        f"<code>{code}</code>"
                        ),
                        parse_mode="HTML"
                    )
        except Exception:
            logging.exception("Ошибка в check_mails_task")
        await asyncio.sleep(60)  # Пауза между проверками


# =====TG-MARKDOWN

def gpt_markdown_to_telegram_html(markdown_text: str) -> str:
    # Экранируем HTML, чтобы избежать конфликтов
    text = html.escape(markdown_text)

    # Жирный текст **...**
    text = re.sub(r"\*\*(.+?)\*\*", r"<b>\1</b>", text)

    # Курсив *...*
    text = re.sub(r"\*(.+?)\*", r"<i>\1</i>", text)

    # Маркированные списки
    text = re.sub(r"^\s*-\s+", "• ", text, flags=re.MULTILINE)

    # Нумерованные списки (без ссылок на группы)
    text = re.sub(r"^\s*(\d+)\.\s+", r"\1. ", text, flags=re.MULTILINE)

    # <br> → перенос строки
    text = text.replace("<br>", "\n")

    # Убираем лишние переносы
    text = re.sub(r"\n{3,}", "\n\n", text)

    return text.strip()


# === Стартап-хук ===
async def on_startup(bot: Bot):
    logging.info("Bot started")
    asyncio.create_task(check_mails_task(bot, CHAT_ID))

# === Точка входа ===
async def main():
    dp.startup.register(on_startup)
    # Контекст-менеджер гарантирует корректное закрытие aiohttp-сессии бота
    async with Bot(TG_BOT_TOKEN) as bot:
        await dp.start_polling(bot)  # или: await dp.run_polling(bot)

if __name__ == "__main__":
    asyncio.run(main())