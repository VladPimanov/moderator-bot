import asyncio
import re
import logging
from datetime import datetime, timedelta
from telegram import Update, ChatPermissions
from telegram.ext import (
    Application,
    CommandHandler,
    MessageHandler,
    ContextTypes,
    filters
)
from config import Config
from service_for_moderation import toxicity_classifier
from virustotal_scanner import vt_scanner

# Настройка логирования
logging.basicConfig(
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s',
    level=logging.INFO
)
logger = logging.getLogger(__name__)

# Инициализация параметров из конфига
TOKEN = Config.TOKEN
BANNED_WORDS = Config.BANNED_WORDS
SPAM_LIMIT = Config.SPAM_LIMIT
DEFAULT_MUTE_DURATION = Config.MUTE_DURATION
TIME_UPDATE_COUNT_MESSAGES = Config.TIME_UPDATE_COUNT_MESSAGES
TOXICITY_THRESHOLD = Config.TOXICITY_THRESHOLD

DEFAULT_CHAT_SETTINGS = Config.DEFAULT_CHAT_SETTINGS

# Глобальные переменные для отслеживания активности
user_warnings = {}           # Ключ: (chat_id, user_id)
user_message_timestamps = {} # Ключ: (chat_id, user_id) -> [timestamp1, timestamp2, ...]
user_mute_status = {}        # Ключ: (chat_id, user_id)
chat_admins = {}             # {chat_id: [admin_id1, admin_id2]}
chat_settings = {}           # {chat_id: settings_dict}

async def get_chat_admins(chat_id: int, context: ContextTypes.DEFAULT_TYPE) -> list:
    """Получаем список администраторов чата"""
    try:
        admins = await context.bot.get_chat_administrators(chat_id)
        return [admin.user.id for admin in admins]
    except Exception as e:
        logger.error(f"Ошибка получения администраторов чата {chat_id}: {str(e)}")
        return []

async def is_user_admin(chat_id: int, user_id: int, context: ContextTypes.DEFAULT_TYPE) -> bool:
    """Проверяем, является ли пользователь администратором"""
    if chat_id not in chat_admins:
        chat_admins[chat_id] = await get_chat_admins(chat_id, context)
    return user_id in chat_admins[chat_id]

async def get_chat_settings(chat_id: int) -> dict:
    """Получаем настройки для чата (создаем если нужно)"""
    if chat_id not in chat_settings:
        chat_settings[chat_id] = DEFAULT_CHAT_SETTINGS.copy()
    return chat_settings[chat_id]

async def update_chat_setting(chat_id: int, setting: str, value) -> bool:
    """Обновляем настройку чата"""
    settings = await get_chat_settings(chat_id)
    if setting in settings:
        settings[setting] = value
        return True
    return False

async def ban_user(update: Update, context: ContextTypes.DEFAULT_TYPE) -> None:
    """Бан пользователя по reply к сообщению (работает во всех типах чатов)"""
    chat_id = update.effective_chat.id
    user_id = update.effective_user.id
    
    if not await is_user_admin(chat_id, user_id, context):
        await update.message.reply_text("❌ У вас нет прав для выполнения этой команды.")
        return
    
    if not update.message.reply_to_message:
        await update.message.reply_text("ℹ️ Команда должна быть отправлена в ответ на сообщение пользователя.")
        return
    
    try:
        target_id = update.message.reply_to_message.from_user.id
        username = update.message.reply_to_message.from_user.username or "пользователь"
        await context.bot.ban_chat_member(chat_id=chat_id, user_id=target_id)
        await update.message.reply_text(f"✅ Пользователь @{username} забанен.")
    except Exception as e:
        logger.error(f"Ban error: {str(e)}")
        await update.message.reply_text(f"⚠️ Ошибка: {str(e)}")

async def unmute_user(chat_id: int, user_id: int, context: ContextTypes.DEFAULT_TYPE) -> None:
    """Автоматическое снятие мута после таймаута"""
    settings = await get_chat_settings(chat_id)
    mute_duration = settings.get('mute_duration', DEFAULT_MUTE_DURATION)
    
    await asyncio.sleep(mute_duration)
    mute_key = (chat_id, user_id)
    try:
        if mute_key in user_mute_status and user_mute_status[mute_key]:
            # Сбрасываем статус мута
            user_mute_status[mute_key] = False
            
            # Получаем текущее имя пользователя
            try:
                member = await context.bot.get_chat_member(chat_id, user_id)
                username = member.user.username or "пользователь"
                await context.bot.send_message(chat_id, f"🔊 Пользователь @{username} размучен.")
            except:
                logger.warning(f"Could not send unmute message for user {user_id}")
    except Exception as e:
        logger.error(f"Unmute error: {str(e)}")

async def mute_user(update: Update, context: ContextTypes.DEFAULT_TYPE) -> None:
    """Мьют пользователя с поддержкой всех типов чатов"""
    chat_id = update.effective_chat.id
    user_id = update.effective_user.id
    
    if not await is_user_admin(chat_id, user_id, context):
        await update.message.reply_text("❌ У вас нет прав для выполнения этой команды.")
        return
    
    if not update.message.reply_to_message:
        await update.message.reply_text("ℹ️ Команда должна быть отправлена в ответ на сообщение пользователя.")
        return
    
    try:
        settings = await get_chat_settings(chat_id)
        mute_duration = settings.get('mute_duration', DEFAULT_MUTE_DURATION)
        
        target_id = update.message.reply_to_message.from_user.id
        username = update.message.reply_to_message.from_user.username or "пользователь"
        chat_type = update.effective_chat.type
        mute_key = (chat_id, target_id)
        
        # Проверяем, не замьючен ли уже пользователь
        if mute_key in user_mute_status and user_mute_status[mute_key]:
            await update.message.reply_text(f"ℹ️ Пользователь @{username} уже замьючен.")
            return
            
        # Проверяем, что пользователь все еще в чате
        try:
            member = await context.bot.get_chat_member(chat_id, target_id)
            if member.status in ['left', 'kicked']:
                await update.message.reply_text(f"ℹ️ Пользователь @{username} вышел из чата.")
                return
        except Exception as e:
            logger.warning(f"Failed to check user status: {str(e)}")
            await update.message.reply_text(f"⚠️ Не удалось проверить статус пользователя.")
            return
            
        # Для супергрупп используем стандартный метод
        if chat_type == "supergroup":
            try:
                permissions = ChatPermissions(can_send_messages=False)
                await context.bot.restrict_chat_member(chat_id, target_id, permissions)
            except Exception as e:
                logger.error(f"Restrict error in supergroup: {str(e)}")
                await update.message.reply_text(f"⚠️ Ошибка при муте: {str(e)}")
                return
        else:
            # В обычных группах просто устанавливаем статус мута
            pass
        
        # Устанавливаем статус мута для всех типов чатов
        user_mute_status[mute_key] = True
        await update.message.reply_text(f"🔇 Пользователь @{username} заглушен на {mute_duration} сек.")
        
        # Запускаем задачу для автоматического размута
        asyncio.create_task(unmute_user(chat_id, target_id, context))
        
    except Exception as e:
        if "User_not_participant" in str(e):
            await update.message.reply_text(f"ℹ️ Пользователь @{username} вышел из чата.")
        else:
            logger.error(f"Mute error: {str(e)}")
            await update.message.reply_text(f"⚠️ Ошибка: {str(e)}")

async def warn_user(update: Update, context: ContextTypes.DEFAULT_TYPE) -> None:
    """Выдача предупреждения (работает во всех типах чатов)"""
    chat_id = update.effective_chat.id
    user_id = update.effective_user.id
    
    if not await is_user_admin(chat_id, user_id, context):
        await update.message.reply_text("❌ У вас нет прав для выполнения этой команды.")
        return
    
    if not update.message.reply_to_message:
        await update.message.reply_text("ℹ️ Команда должна быть отправлена в ответ на сообщение пользователя.")
        return
    
    # Проверяем, включена ли система предупреждений в этом чате
    settings = await get_chat_settings(chat_id)
    if not settings['enable_warnings']:
        await update.message.reply_text("ℹ️ Система предупреждений отключена в этом чате.")
        return
    
    try:
        target_id = update.message.reply_to_message.from_user.id
        username = update.message.reply_to_message.from_user.username or "пользователь"
        warn_key = (chat_id, target_id)
        
        user_warnings[warn_key] = user_warnings.get(warn_key, 0) + 1
        warnings_count = user_warnings[warn_key]

        if warnings_count >= 3:
            # При 3 предупреждениях - бан
            await context.bot.ban_chat_member(chat_id, target_id)
            await update.message.reply_text(f"⛔ Пользователь @{username} забанен за 3 предупреждения.")
            # Сбрасываем счетчик предупреждений после бана
            user_warnings[warn_key] = 0
        else:
            await update.message.reply_text(f"⚠️ Предупреждение {warnings_count}/3 для @{username}")
    except Exception as e:
        logger.error(f"Warn error: {str(e)}")
        await update.message.reply_text(f"⚠️ Ошибка: {str(e)}")

async def check_message(update: Update, context: ContextTypes.DEFAULT_TYPE) -> None:
    """Фильтр спама, токсичности, запрещённых слов и опасных ссылок"""
    if not update.message or not update.message.text:
        return
    
    user_id = update.effective_user.id
    chat_id = update.effective_chat.id
    username = update.effective_user.username or "пользователь"
    chat_type = update.effective_chat.type
    mute_key = (chat_id, user_id)
    
    # Получаем настройки чата
    settings = await get_chat_settings(chat_id)
    
    # Проверяем, не замьючен ли пользователь
    if mute_key in user_mute_status and user_mute_status[mute_key]:
        try:
            await context.bot.delete_message(chat_id, update.message.message_id)
            logger.info(f"Deleted message from muted user {user_id} in chat {chat_id}")
        except:
            pass
        return

    try:
        # Проверяем, является ли пользователь администратором
        is_admin = await is_user_admin(chat_id, user_id, context)
        
        # 1. Проверка на запрещённые слова (для всех)
        if settings['enable_banned_words_filter']:
            text_lower = update.message.text.lower()
            if any(banned_word in text_lower for banned_word in BANNED_WORDS):
                await context.bot.delete_message(chat_id, update.message.message_id)
                await context.bot.send_message(
                    chat_id,
                    f"🚫 Сообщение от @{username} удалено за нарушение правил."
                )
                return

        # 2. Проверка на ссылки (только для обычных пользователей)
        url_pattern = r'(?:https?://|www\.|\b)[a-zA-Z0-9-]+\.[a-zA-Z]{2,}(?:\.[a-zA-Z]{2,})*\S*'
        url_matches = re.findall(url_pattern, update.message.text)

        if url_matches and not is_admin:
            # Если включен общий фильтр ссылок
            if settings['enable_link_filter']:
                # Для обычных пользователей - сразу удаляем сообщение с любой ссылкой
                await context.bot.delete_message(chat_id, update.message.message_id)
                # Отправляем сообщение без указания ссылок
                await context.bot.send_message(
                    chat_id,
                    f"🚫 Сообщение от @{username} удалено: обычным пользователям запрещено отправлять ссылки."
                )
                return
            # Если ссылки разрешены, но включена проверка безопасности
            elif settings['enable_virustotal'] and vt_scanner:
                # Проверяем каждую ссылку, пока не найдем опасную
                for url in url_matches:
                    # Нормализация URL
                    normalized_url = url
                    if not url.startswith(('http://', 'https://')):
                        if url.startswith('www.'):
                            normalized_url = 'https://' + url
                        else:
                            normalized_url = 'https://' + url
                    
                    # Проверка через VirusTotal
                    is_dangerous, detail = vt_scanner.get_url_reputation(normalized_url)
                    if is_dangerous:
                        # Нашли опасную ссылку - удаляем сообщение
                        await context.bot.delete_message(chat_id, update.message.message_id)
                        # Отправляем сообщение без указания ссылок
                        await context.bot.send_message(
                            chat_id,
                            f"🚫 Сообщение от @{username} удалено: обнаружены опасные ссылки."
                        )
                        return
                
        # 3. Проверка на спам (исключая администраторов)
        if settings['enable_spam_filter']:
            timestamp_key = (chat_id, user_id)
            current_time = datetime.now()
            
            if timestamp_key not in user_message_timestamps:
                user_message_timestamps[timestamp_key] = []
            
            # Удаляем старые сообщения
            user_message_timestamps[timestamp_key] = [
                ts for ts in user_message_timestamps[timestamp_key] 
                if (current_time - ts).total_seconds() <= TIME_UPDATE_COUNT_MESSAGES
            ]
            
            # Добавляем текущее сообщение
            user_message_timestamps[timestamp_key].append(current_time)
            message_count = len(user_message_timestamps[timestamp_key])
            
            logger.debug(f"User @{username} message count: {message_count} (last {TIME_UPDATE_COUNT_MESSAGES} sec)")
            
            # Проверяем превышение лимита (только для обычных пользователей)
            if (message_count > SPAM_LIMIT 
                    and not (mute_key in user_mute_status and user_mute_status[mute_key])
                    and not is_admin):
                try:
                    # Удаляем спам-сообщение
                    await context.bot.delete_message(chat_id, update.message.message_id)
                    
                    # Проверяем, что пользователь все еще в чате
                    try:
                        member = await context.bot.get_chat_member(chat_id, user_id)
                        if member.status in ['left', 'kicked']:
                            logger.info(f"User @{username} has left the chat, skipping mute")
                            return
                    except Exception as e:
                        logger.warning(f"Failed to check user status: {str(e)}")
                        return

                    # Устанавливаем статус мута
                    user_mute_status[mute_key] = True
                    
                    # Отправляем сообщение о муте
                    settings = await get_chat_settings(chat_id)
                    mute_duration = settings.get('mute_duration', DEFAULT_MUTE_DURATION)
                    await context.bot.send_message(
                        chat_id,
                        f"🔇 Флуд! @{username} получил мут на {mute_duration} сек. ({message_count} сообщений за последние {TIME_UPDATE_COUNT_MESSAGES} сек.)"
                    )
                    
                    # Запускаем задачу для автоматического размута
                    asyncio.create_task(unmute_user(chat_id, user_id, context))
                    
                except Exception as e:
                    logger.error(f"Spam processing error: {str(e)}")
                return

        # 4. Проверка на токсичность (для всех пользователей)
        if settings['enable_toxicity_filter']:
            try:
                if toxicity_classifier:
                    is_toxic, prob = toxicity_classifier.predict_toxicity(update.message.text)
                    if prob > TOXICITY_THRESHOLD:
                        await context.bot.delete_message(chat_id, update.message.message_id)
                        await context.bot.send_message(
                            chat_id,
                            f"🚫 Сообщение от @{username} удалено за токсичность (вероятность: {prob:.2f})."
                        )
                        return
            except Exception as e:
                logger.error(f"Toxicity check error: {str(e)}")

    except Exception as e:
        logger.error(f"Message processing error: {str(e)}")

async def start(update: Update, context: ContextTypes.DEFAULT_TYPE) -> None:
    """Приветственное сообщение."""
    await update.message.reply_text(
        "🤖 Привет! Я бот-модератор. Мои функции:\n"
        "- Автоматическое удаление токсичных сообщений\n"
        "- Блокировка спама и флуда\n"
        "- Защита от запрещенных слов и ссылок\n\n"
        "Команды для админов:\n"
        "/ban - забанить пользователя (ответом на сообщение)\n"
        f"/mute - замутить пользователя\n"
        "/warn - выдать предупреждение\n"
        "/settings - показать текущие настройки\n"
        "/enable <фильтр> - включить фильтр\n"
        "/disable <фильтр> - выключить фильтр\n"
        "/set_mute_duration <секунды> - установить длительность мута\n"
        "/set_links_policy <strict|safe|allow> - политика для ссылок\n"
        "\nДоступные фильтры: toxicity, spam, links, virustotal, banned_words, warnings"
        "\nПолитики для ссылок:"
        "\n- strict: все ссылки запрещены"
        "\n- safe: разрешены только безопасные ссылки"
        "\n- allow: разрешены все ссылки"
    )

async def show_settings(update: Update, context: ContextTypes.DEFAULT_TYPE) -> None:
    """Показать текущие настройки модерации"""
    chat_id = update.effective_chat.id
    user_id = update.effective_user.id
    
    if not await is_user_admin(chat_id, user_id, context):
        await update.message.reply_text("❌ У вас нет прав для выполнения этой команды.")
        return
    
    settings = await get_chat_settings(chat_id)
    
    # Определяем политику ссылок
    if settings['enable_link_filter']:
        link_policy = "🔒 Все ссылки запрещены"
    elif settings['enable_virustotal']:
        link_policy = "🛡️ Только безопасные ссылки"
    else:
        link_policy = "🔓 Разрешены все ссылки"
    
    message = (
        "⚙️ Текущие настройки модерации:\n"
        f"• Проверка токсичности: {'✅ включена' if settings['enable_toxicity_filter'] else '❌ выключена'}\n"
        f"• Антиспам система: {'✅ включена' if settings['enable_spam_filter'] else '❌ выключена'}\n"
        f"• Фильтр запрещенных слов: {'✅ включен' if settings['enable_banned_words_filter'] else '❌ выключен'}\n"
        f"• Система предупреждений: {'✅ включена' if settings['enable_warnings'] else '❌ выключена'}\n"
        f"• Политика ссылок: {link_policy}\n"
        f"• Длительность мута: {settings['mute_duration']} сек"
    )
    
    await update.message.reply_text(message)

async def toggle_setting(update: Update, context: ContextTypes.DEFAULT_TYPE, enable: bool) -> None:
    """Включить/выключить настройку"""
    chat_id = update.effective_chat.id
    user_id = update.effective_user.id
    
    if not await is_user_admin(chat_id, user_id, context):
        await update.message.reply_text("❌ У вас нет прав для выполнения этой команды.")
        return
    
    if not context.args:
        action = "включить" if enable else "выключить"
        await update.message.reply_text(f"ℹ️ Укажите настройку для {action}. Например: /{'enable' if enable else 'disable'} spam")
        return
    
    setting_name = context.args[0].lower()
    setting_map = {
        'toxicity': 'enable_toxicity_filter',
        'spam': 'enable_spam_filter',
        'links': 'enable_link_filter',
        'virustotal': 'enable_virustotal',
        'banned_words': 'enable_banned_words_filter',
        'warnings': 'enable_warnings'
    }
    
    if setting_name not in setting_map:
        valid_settings = ", ".join(setting_map.keys())
        await update.message.reply_text(f"❌ Неверная настройка. Допустимые значения: {valid_settings}")
        return
    
    setting_key = setting_map[setting_name]
    success = await update_chat_setting(chat_id, setting_key, enable)
    
    if success:
        action = "включен" if enable else "выключен"
        await update.message.reply_text(f"✅ Фильтр '{setting_name}' успешно {action}.")
    else:
        await update.message.reply_text("⚠️ Ошибка при изменении настроек.")

async def set_mute_duration(update: Update, context: ContextTypes.DEFAULT_TYPE) -> None:
    """Установить длительность мута"""
    chat_id = update.effective_chat.id
    user_id = update.effective_user.id
    
    if not await is_user_admin(chat_id, user_id, context):
        await update.message.reply_text("❌ У вас нет прав для выполнения этой команды.")
        return
    
    if not context.args or not context.args[0].isdigit():
        await update.message.reply_text("ℹ️ Укажите длительность мута в секундах. Например: /set_mute_duration 60")
        return
    
    duration = int(context.args[0])
    if duration < 10 or duration > 86400:  # От 10 секунд до 1 дня
        await update.message.reply_text("❌ Длительность мута должна быть от 10 секунд до 86400 секунд (1 день).")
        return
    
    success = await update_chat_setting(chat_id, 'mute_duration', duration)
    
    if success:
        await update.message.reply_text(f"✅ Длительность мута установлена: {duration} сек.")
    else:
        await update.message.reply_text("⚠️ Ошибка при изменении настроек.")

async def set_links_policy(update: Update, context: ContextTypes.DEFAULT_TYPE) -> None:
    """Установить политику для ссылок"""
    chat_id = update.effective_chat.id
    user_id = update.effective_user.id
    
    if not await is_user_admin(chat_id, user_id, context):
        await update.message.reply_text("❌ У вас нет прав для выполнения этой команды.")
        return
    
    if not context.args:
        await update.message.reply_text("ℹ️ Укажите политику для ссылок: strict, safe или allow. Например: /set_links_policy safe")
        return
    
    policy = context.args[0].lower()
    
    if policy == 'strict':
        await update_chat_setting(chat_id, 'enable_link_filter', True)
        await update_chat_setting(chat_id, 'enable_virustotal', False)
        await update.message.reply_text("✅ Политика ссылок: 🔒 Все ссылки запрещены для обычных пользователей.")
    elif policy == 'safe':
        await update_chat_setting(chat_id, 'enable_link_filter', False)
        await update_chat_setting(chat_id, 'enable_virustotal', True)
        await update.message.reply_text("✅ Политика ссылок: 🛡️ Разрешены только безопасные ссылки (проверка через VirusTotal).")
    elif policy == 'allow':
        await update_chat_setting(chat_id, 'enable_link_filter', False)
        await update_chat_setting(chat_id, 'enable_virustotal', False)
        await update.message.reply_text("✅ Политика ссылок: 🔓 Разрешены все ссылки для обычных пользователей.")
    else:
        await update.message.reply_text("❌ Неверная политика. Допустимые значения: strict, safe, allow")

async def enable_setting(update: Update, context: ContextTypes.DEFAULT_TYPE) -> None:
    """Включить настройку"""
    await toggle_setting(update, context, True)

async def disable_setting(update: Update, context: ContextTypes.DEFAULT_TYPE) -> None:
    """Выключить настройку"""
    await toggle_setting(update, context, False)

async def cleanup_old_messages(context: ContextTypes.DEFAULT_TYPE) -> None:
    """Периодическая очистка старых записей о сообщениях"""
    current_time = datetime.now()
    keys_to_delete = []
    
    for key, timestamps in user_message_timestamps.items():
        updated_timestamps = [
            ts for ts in timestamps 
            if (current_time - ts).total_seconds() <= TIME_UPDATE_COUNT_MESSAGES
        ]
        
        if updated_timestamps:
            user_message_timestamps[key] = updated_timestamps
        else:
            keys_to_delete.append(key)
    
    for key in keys_to_delete:
        del user_message_timestamps[key]
    
    logger.info(f"Очистка старых сообщений: удалено {len(keys_to_delete)} записей")

async def refresh_admins(context: ContextTypes.DEFAULT_TYPE) -> None:
    """Периодическое обновление списка администраторов"""
    for chat_id in list(chat_admins.keys()):
        try:
            chat_admins[chat_id] = await get_chat_admins(chat_id, context.bot)
            logger.info(f"Обновлены администраторы чата {chat_id}")
        except Exception as e:
            logger.error(f"Ошибка обновления администраторов чата {chat_id}: {str(e)}")

def main() -> None:
    """Запуск бота."""
    logger.info("🤖 Бот запускается...")
    
    try:
        app = Application.builder().token(TOKEN).build()

        # Регистрация обработчиков команд
        app.add_handler(CommandHandler("start", start))
        app.add_handler(CommandHandler("ban", ban_user))
        app.add_handler(CommandHandler("mute", mute_user))
        app.add_handler(CommandHandler("warn", warn_user))
        app.add_handler(CommandHandler("settings", show_settings))
        app.add_handler(CommandHandler("enable", enable_setting))
        app.add_handler(CommandHandler("disable", disable_setting))
        app.add_handler(CommandHandler("set_mute_duration", set_mute_duration))
        app.add_handler(CommandHandler("set_links_policy", set_links_policy))
        
        # Обработчик текстовых сообщений
        app.add_handler(MessageHandler(filters.TEXT & ~filters.COMMAND, check_message))
        
        # Периодические задачи
        job_queue = app.job_queue
        if job_queue:
            job_queue.run_repeating(
                cleanup_old_messages,
                interval=60,
                first=0
            )
            job_queue.run_repeating(
                refresh_admins,
                interval=600,
                first=0
            )

        logger.info("🔄 Бот запущен и ожидает сообщений...")
        app.run_polling()
    except Exception as e:
        logger.error(f"🚨 Ошибка при запуске бота: {str(e)}")

if __name__ == "__main__":
    main()