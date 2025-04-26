import re
from telegram import Update, ChatPermissions
from telegram.ext import (
    Application,
    CommandHandler,
    MessageHandler,
    ContextTypes,
    filters
)

TOKEN = "7902441298:AAFXdV30BpSIkdEek1QXRZJOLr3aJjq-9Zk"
ADMIN_IDS = []
BANNED_WORDS = ["мат", "мат2"]
SPAM_LIMIT = 5

user_warnings = {}
user_message_count = {}


async def ban_user(update: Update, context: ContextTypes.DEFAULT_TYPE) -> None:
    """Бан пользователя по reply к сообщению."""
    if update.effective_user.id not in ADMIN_IDS:
        return
    user_id = update.message.reply_to_message.from_user.id
    await context.bot.ban_chat_member(update.effective_chat.id, user_id)
    await update.message.reply_text("Пользователь забанен.")


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
    """Фильтр спама и запрещённых слов."""
    user_id = update.effective_user.id
    chat_id = update.effective_chat.id

    user_message_count[user_id] = user_message_count.get(user_id, 0) + 1
    if user_message_count[user_id] > SPAM_LIMIT:
        await context.bot.delete_message(chat_id, update.message.message_id)
        await context.bot.send_message(chat_id, f"Флуд! @{update.effective_user.username} получил мут.")
        permissions = ChatPermissions(can_send_messages=False)
        await context.bot.restrict_chat_member(chat_id, user_id, permissions)

    if any(word in update.message.text.lower() for word in BANNED_WORDS):
        await context.bot.delete_message(chat_id, update.message.message_id)
        await context.bot.send_message(chat_id, "Сообщение удалено за нарушение правил.")

    if re.search(r'(http|https|t.me|@)\S+', update.message.text):
        if update.effective_user.id not in ADMIN_IDS:
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