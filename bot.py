import asyncio
import re
from telegram import Update, ChatPermissions
from telegram.ext import (
    Application,
    CommandHandler,
    MessageHandler,
    ContextTypes,
    filters
)
from datetime import datetime
from urlScanner import VirusTotalURLScanner


TOKEN = "TOKEN"
ADMIN_IDS = []
BANNED_WORDS = ["мат", "мат2"]
SPAM_LIMIT = 5
MUTE_DURATION = 10
TIME_UPDATE_COUNT_MESSAGES = 60

current_time = datetime.now()

user_warnings = {}
user_message_count = {}
user_message_times = {}


async def ban_user(update: Update, context: ContextTypes.DEFAULT_TYPE) -> None:
    """Бан пользователя по reply к сообщению."""
    if update.effective_user.id not in ADMIN_IDS:
        return
    user_id = update.message.reply_to_message.from_user.id
    await context.bot.ban_chat_member(update.effective_chat.id, user_id)
    await update.message.reply_text("Пользователь забанен.")

async def unmute_user(chat_id: int, user_id: int , username: str, context) -> None:
    await asyncio.sleep(MUTE_DURATION)
    user_message_count[user_id] = 0
    permissions = ChatPermissions(can_send_messages=True)
    await context.bot.restrict_chat_member(chat_id, user_id, permissions)
    await context.bot.send_message(chat_id, f"Пользователь @{username} размучен.")

async def mute_user(update: Update, context: ContextTypes.DEFAULT_TYPE) -> None:
    """Мьют пользователя."""
    if update.effective_user.id not in ADMIN_IDS:
        return
    user_id = update.message.reply_to_message.from_user.id
    permissions = ChatPermissions(can_send_messages=False)
    await context.bot.restrict_chat_member(update.effective_chat.id, user_id, permissions)
    await update.message.reply_text("Пользователь заглушен.")




async def warn_user(update: Update, context: ContextTypes.DEFAULT_TYPE) -> None:
    """Выдача предупреждения."""
    if update.effective_user.id not in ADMIN_IDS:
        return
    user_id = update.message.reply_to_message.from_user.id
    user_warnings[user_id] = user_warnings.get(user_id, 0) + 1

    if user_warnings[user_id] >= 3:
        await context.bot.ban_chat_member(update.effective_chat.id, user_id)
        await update.message.reply_text("Пользователь забанен за 3 предупреждения.")
    else:
        await update.message.reply_text(f"Предупреждение {user_warnings[user_id]}/3")


async def check_spam(update: Update, context: ContextTypes.DEFAULT_TYPE) -> None:
    global user_message_count
    """Фильтр спама и запрещённых слов."""
    user_id = update.effective_user.id
    chat_id = update.effective_chat.id
    username = update.effective_user.username

    delta_time = int(float(str(datetime.now() - current_time).split(':')[-1][1:]))

    if delta_time > TIME_UPDATE_COUNT_MESSAGES:
        user_message_count = {}

    user_message_count[user_id] = user_message_count.get(user_id, 0) + 1
    if user_message_count[user_id] > SPAM_LIMIT:

        await context.bot.delete_message(chat_id, update.message.message_id)
        await context.bot.send_message(chat_id, f"Флуд! @{username} получил мут на {MUTE_DURATION} сек")
        permissions = ChatPermissions(can_send_messages=False)
        await context.bot.restrict_chat_member(chat_id, user_id, permissions)

        await asyncio.create_task(
            unmute_user(chat_id,user_id, username , context))



    if any(word in update.message.text.lower() for word in BANNED_WORDS):
        await context.bot.delete_message(chat_id, update.message.message_id)
        await context.bot.send_message(chat_id, "Сообщение удалено за нарушение правил.")

    if re.search(r'(http|https|t.me|@)\S+', update.message.text):
        if update.effective_user.id not in ADMIN_IDS:
            array_words = update.message.text.split(' ')
            for word in array_words:
                if 'http' in word or 't.me' in word:
                    find_url = word
                    if VirusTotalURLScanner.get_url_reputation(find_url) == True:
                        await context.bot.delete_message(chat_id, update.message.message_id)

def main() -> None:
    app = Application.builder().token(TOKEN).build()

    app.add_handler(CommandHandler("ban", ban_user))
    app.add_handler(CommandHandler("mute", mute_user))
    app.add_handler(CommandHandler("warn", warn_user))
    app.add_handler(MessageHandler(filters.TEXT & ~filters.COMMAND, check_spam))

    app.run_polling()


if __name__ == "__main__":
    main()