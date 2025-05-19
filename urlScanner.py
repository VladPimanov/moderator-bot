import requests
from time import sleep

class VirusTotalURLScanner:
    def __init__(self, api_key = "api_key"):
        self.api_key = api_key  # API-ключ передаётся напрямую
        self.base_url = "https://www.virustotal.com/api/v3"
        self.headers = {
            "x-apikey": self.api_key,
            "Accept": "application/json"
        }

    def scan_url(self, url):
        """Отправляет URL на сканирование в VirusTotal"""
        response = requests.post(
            f"{self.base_url}/urls",
            headers=self.headers,
            data={"url": url}
        )

        if response.status_code == 200:
            url_id = response.json()["data"]["id"]
            return self._get_url_report(url_id)
        else:
            raise Exception(f"Ошибка при отправке URL: {response.text}")

    def _get_url_report(self, url_id):
        """Получает отчет по URL"""
        while True:
            response = requests.get(
                f"{self.base_url}/analyses/{url_id}",
                headers=self.headers
            )
            data = response.json()

            if data["data"]["attributes"]["status"] == "completed":
                final_url_id = data["meta"]["url_info"]["id"]
                return self._get_final_url_report(final_url_id)
            sleep(10)  # Ожидаем завершения анализа

    def _get_final_url_report(self, url_id):
        """Получает финальный отчет"""
        response = requests.get(
            f"{self.base_url}/urls/{url_id}",
            headers=self.headers
        )
        return response.json()

    def get_url_reputation(self, url):
        """Возвращает краткую сводку по URL"""
        report = self.scan_url(url)
        stats = report["data"]["attributes"]["last_analysis_stats"]
        return stats["malicious"] > 0#True if dangerous


if __name__ == "__main__":
    API_KEY = "api_key"

    scanner = VirusTotalURLScanner(API_KEY)

    url = "https://www.virustotal.com/gui/user/abjora/apikey"
    try:
        result = scanner.get_url_reputation(url)
        if result == True:
          print("dangerous")
        else:
            print("It's not dangerous")
    except Exception as e:
        print(f"Ошибка: {e}")