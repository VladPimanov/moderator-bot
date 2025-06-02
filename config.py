# -*- coding: utf-8 -*-
class Config:
    MODEL_PATH = "app/model/full_model.pth"
    TOKEN = "указать токен"
    VIRUSTOTAL_API_KEY = "указать ключ"
    
    # Дополнительные параметры модерации
    BANNED_WORDS = ["мат1", "мат2", "оскорбление"]  # Запрещенные слова
    SPAM_LIMIT = 5  # Максимальное количество сообщений за период
    MUTE_DURATION = 30  # Длительность мута в секундах
    TIME_UPDATE_COUNT_MESSAGES = 60  # Период сброса счетчика спама в секундах
    TOXICITY_THRESHOLD = 0.6  # Порог для удаления токсичных сообщений
    DEFAULT_CHAT_SETTINGS = {
    'enable_toxicity_filter': True,
    'enable_spam_filter': True,
    'enable_link_filter': True,          # Общий фильтр ссылок, True = запрещены все ссылки
    'enable_virustotal': False,           # Проверка безопасности ссылок
    'enable_banned_words_filter': True,
    'enable_warnings': True,
    'mute_duration': MUTE_DURATION
    }