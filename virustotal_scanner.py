# -*- coding: utf-8 -*-
import requests
import logging
import base64
import re
from config import Config

# Настройка логирования
logging.basicConfig(
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s',
    level=logging.INFO
)
logger = logging.getLogger(__name__)

class VirusTotalURLScanner:
    def __init__(self, api_key):
        self.api_key = api_key
        self.base_url = "https://www.virustotal.com/api/v3"
        self.headers = {
            "x-apikey": self.api_key,
            "Accept": "application/json"
        }
        logger.info("VirusTotal scanner initialized")
    
    def _get_url_id(self, url):
        """Кодирует URL в формат ID для VirusTotal"""
        url_bytes = url.encode('utf-8')
        url_id = base64.urlsafe_b64encode(url_bytes).decode().strip('=')
        return url_id

    def get_url_report(self, url):
        """Получает отчет по URL без ожидания сканирования"""
        try:
            url_id = self._get_url_id(url)
            response = requests.get(
                f"{self.base_url}/urls/{url_id}",
                headers=self.headers,
                timeout=10
            )
            
            if response.status_code == 200:
                return response.json()
            elif response.status_code == 404:
                # URL не найден, отправляем на сканирование
                self.scan_url(url)
                return None
            else:
                logger.error(f"VirusTotal error: {response.status_code} - {response.text}")
                return None
        except Exception as e:
            logger.error(f"VirusTotal report error: {str(e)}")
            return None

    def scan_url(self, url):
        """Отправляет URL на сканирование в VirusTotal"""
        try:
            response = requests.post(
                f"{self.base_url}/urls",
                headers=self.headers,
                data={"url": url},
                timeout=5
            )
            response.raise_for_status()
            return response.json()
        except Exception as e:
            logger.error(f"VirusTotal scan error: {str(e)}")
            return None

    def get_url_reputation(self, url):
        """Проверяет репутацию URL"""
        try:
            report = self.get_url_report(url)
            if not report:
                return False, "Ссылка на проверке"
            
            stats = report["data"]["attributes"]["last_analysis_stats"]
            malicious = stats["malicious"]
            total = sum(stats.values())
            
            return malicious > 0, f"Вредоносных: {malicious}/{total}"
        except Exception as e:
            logger.error(f"VirusTotal reputation error: {str(e)}")
            return False, "Ошибка проверки"

# Инициализация сканера
if hasattr(Config, 'VIRUSTOTAL_API_KEY') and Config.VIRUSTOTAL_API_KEY:
    vt_scanner = VirusTotalURLScanner(Config.VIRUSTOTAL_API_KEY)
else:
    vt_scanner = None
    logger.warning("VirusTotal API key not provided. URL scanning disabled.")