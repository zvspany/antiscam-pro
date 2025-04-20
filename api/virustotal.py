# api/virustotal.py
import requests
import os
import base64

# Wstaw tutaj swój klucz API z VirusTotal
VIRUSTOTAL_API_KEY = os.getenv("VT_API_KEY") or "TWOJ_KLUCZ_API"

def scan_url_with_virustotal(url: str) -> dict:
    """
    Skanuje URL przy użyciu VirusTotal.
    Returns:
        dict: {
            "detected": bool,
            "positives": int,
            "total": int,
            "scan_date": str
        }
    """
    try:
        headers = {"x-apikey": VIRUSTOTAL_API_KEY}
        
        # Przesyłanie URL zakodowanego w base64
        encoded_url = base64.urlsafe_b64encode(url.encode()).decode().strip("=")
        
        # Zajmujemy się zapytaniem o wynik analizy linku
        result_url = f"https://www.virustotal.com/api/v3/urls/{encoded_url}"
        response = requests.get(result_url, headers=headers)
        response.raise_for_status()

        result_data = response.json()["data"]["attributes"]
        stats = result_data.get("last_analysis_stats", {})
        malicious = stats.get("malicious", 0)
        suspicious = stats.get("suspicious", 0)

        return {
            "detected": malicious > 0 or suspicious > 0,
            "positives": malicious + suspicious,
            "total": stats.get("harmless", 0) + malicious + suspicious,
            "scan_date": result_data.get("last_analysis_date", "brak daty")
        }

    except Exception as e:
        print(f"[VirusTotal] Błąd: {e}")
        return {
            "detected": False,
            "positives": 0,
            "total": 0,
            "scan_date": None
        }
