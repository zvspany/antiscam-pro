# api/virustotal.py
import requests
import os
import base64
import logging
from datetime import datetime # Importuj tylko datetime

logger = logging.getLogger(__name__)

# Pobranie klucza API z ENV lub użyj domyślnego (powinien być zmieniony!)
VIRUSTOTAL_API_KEY = os.getenv("VT_API_KEY")

# Ostrzeżenie, jeśli klucz nie jest ustawiony
if not VIRUSTOTAL_API_KEY or VIRUSTOTAL_API_KEY == "TWOJ_KLUCZ_API":
    logger.warning("VIRUSTOTAL_API_KEY nie jest ustawiony w zmiennych środowiskowych ani nie zmieniono domyślnej wartości w kodzie.")
    # Optionally, you might want to raise an error or disable VT checks entirely if the key is missing.

# Usunięto importy pytz i tzlocal oraz logikę wykrywania SERVER_LOCAL_TZ

def scan_url_with_virustotal(url: str) -> dict:
    """
    Skanuje URL przy użyciu VirusTotal API v3.
    Pobiera istniejący raport skanowania dla danego URL.
    (Nie inicjuje nowego skanowania, jeśli raport nie istnieje)

    Args:
        url (str): URL do zeskanowania.

    Returns:
        dict: Słownik zawierający wyniki skanowania VirusTotal.
              {
                  "detected": bool, # True if malicious or suspicious > 0
                  "positives": int, # Sum of malicious and suspicious counts
                  "total": int,     # Sum of counts for harmless, malicious, suspicious categories etc.
                  "scan_date": str, # Formatted scan date string in UTC or "N/A"
                  "error": str      # Error message if request fails
              }
    """
    if not VIRUSTOTAL_API_KEY or VIRUSTOTAL_API_KEY == "TWOJ_KLUCZ_API":
        return {"detected": False, "positives": 0, "total": 0, "scan_date": "N/A", "error": "API key missing or default"}


    api_url_base = "https://www.virustotal.com/api/v3/urls/"
    headers = {"x-apikey": VIRUSTOTAL_API_KEY}

    try:
        # VirusTotal API v3 wymaga base64url encoded URL bez paddingu
        # https://developers.virustotal.com/v3.0/reference/#urls-id
        encoded_url = base64.urlsafe_b64encode(url.encode()).decode().strip("=")

        # URL do pobrania analizy
        analysis_url = f"{api_url_base}{encoded_url}"

        logger.info(f"Querying VirusTotal for URL: {url}")
        response = requests.get(analysis_url, headers=headers)

        # Sprawdź status odpowiedzi
        if response.status_code == 404:
             logger.info(f"VirusTotal: URL not found in database: {url}")
             return {"detected": False, "positives": 0, "total": 0, "scan_date": "N/A", "message": "URL not found in VT database"}
        elif response.status_code == 401:
             logger.error("VirusTotal API error: Invalid API key")
             return {"detected": False, "positives": 0, "total": 0, "scan_date": "N/A", "error": "Invalid API key"}
        elif response.status_code == 429:
             logger.warning("VirusTotal API error: Rate limit exceeded")
             return {"detected": False, "positives": 0, "total": 0, "scan_date": "N/A", "error": "Rate limit exceeded"}
        elif response.status_code >= 400: # Obsłuż inne błędy HTTP 4xx/5xx
             error_message = f"HTTP error {response.status_code}"
             try:
                 error_data = response.json()
                 error_message += f": {error_data.get('error', {}).get('message', 'Unknown VT error')}"
             except:
                 pass # Ignore if JSON parsing fails
             logger.error(f"VirusTotal HTTP error for {url}: {error_message}")
             return {"detected": False, "positives": 0, "total": 0, "scan_date": "N/A", "error": error_message}

        # Jeśli status 200 OK, przetwarzaj dane
        data = response.json()
        attributes = data.get("data", {}).get("attributes", {})
        stats = attributes.get("last_analysis_stats", {})

        malicious = stats.get("malicious", 0)
        suspicious = stats.get("suspicious", 0)

        # Calculate total engines based on the stats provided
        total_engines = stats.get("harmless", 0) + malicious + suspicious + stats.get("undetected", 0) + stats.get("timeout", 0) + stats.get("failure", 0)

        scan_date_ts = attributes.get("last_analysis_date") # Timestamp (seconds since epoch UTC)
        scan_date_str = "N/A"
        if scan_date_ts:
            try:
                # Konwersja timestampu na obiekt datetime w UTC (naive)
                utc_dt = datetime.utcfromtimestamp(scan_date_ts)
                # Formatuj datę i czas, dodając na końcu " UTC"
                scan_date_str = utc_dt.strftime('%Y-%m-%d %H:%M:%S') + ' UTC'

            except Exception as date_e:
                logger.error(f"Error formatting VirusTotal scan date timestamp {scan_date_ts}: {date_e}")
                scan_date_str = "Invalid Date Format"


        return {
            "detected": (malicious + suspicious) > 0,
            "positives": malicious + suspicious,
            "total": total_engines,
            "scan_date": scan_date_str, # Return formatted date string in UTC
            "error": None # No error
        }

    except requests.exceptions.RequestException as req_err:
        logger.error(f"VirusTotal request failed for {url}: {req_err}")
        return {"detected": False, "positives": 0, "total": 0, "scan_date": "N/A", "error": f"Request failed: {req_err}"}

    except Exception as e:
        logger.error(f"An unexpected error occurred during VirusTotal check for {url}: {e}")
        return {"detected": False, "positives": 0, "total": 0, "scan_date": "N/A", "error": f"Unexpected error: {e}"}