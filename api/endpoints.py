import re
import os
import requests
import base64
from .utils import load_keywords, load_numbers, load_domains, load_shorteners
from .validators import Validators
from transformers import pipeline

# Pobranie klucza API VirusTotal z ENV
VIRUSTOTAL_API_KEY = os.getenv("VT_API_KEY")

# Inicjalizacja AI modelu
try:
    spam_classifier = pipeline("text-classification", model="mrm8488/bert-tiny-finetuned-sms-spam-detection")
except Exception as e:
    print(f"[WARN] Nie udało się załadować modelu AI: {e}")
    spam_classifier = None

def check_message(text: str) -> dict:
    result = {
        "suspicious_words": [],
        "ai_result": None,
        "is_suspicious": False
    }

    keywords = load_keywords()
    result["suspicious_words"] = [kw for kw in keywords if kw in text.lower()]
    result["suspicious_words"] = [word for word in result["suspicious_words"] if word.strip()]

    if spam_classifier:
        prediction = spam_classifier(text)[0]
        label = prediction["label"]
        confidence = round(prediction["score"], 4)
        result["ai_result"] = {
            "label": "SPAM" if label == "LABEL_1" else "HAM",
            "confidence": confidence
        }
        result["is_suspicious"] = (label == "LABEL_1" and confidence > 0.6) or bool(result["suspicious_words"])
    else:
        result["is_suspicious"] = bool(result["suspicious_words"])

    return result

def check_phone(number: str) -> dict:
    known_scams = load_numbers()
    return {
        "is_valid": Validators.is_valid_phone(number),
        "is_suspicious": number in known_scams
    }

def check_link(link: str) -> dict:
    suspicious_reasons = []
    link_clean = link.lower()

    is_valid = Validators.is_valid_url(link)
    if not is_valid:
        return {
            "is_valid": False,
            "is_suspicious": False,
            "suspicious_words": ["invalid_format"]
        }

    suspicious_patterns = ["free", "gift", "login", "verify", "paypal", "bank", ".ru", ".cn"]
    for pattern in suspicious_patterns:
        if pattern in link_clean:
            suspicious_reasons.append(f"Suspicious pattern: {pattern}")

    scam_domains = load_domains()
    for domain in scam_domains:
        if domain in link_clean:
            suspicious_reasons.append(f"Domain reported as suspicious: {domain}")

    shorteners = load_shorteners()
    for short in shorteners:
        if short in link_clean:
            suspicious_reasons.append(f"Link shortener: {short}")

    return {
        "is_valid": True,
        "is_suspicious": bool(suspicious_reasons),
        "suspicious_words": suspicious_reasons
    }

def check_virustotal(url: str) -> dict:
    api_url = "https://www.virustotal.com/api/v3/urls/"
    headers = {
        "x-apikey": VIRUSTOTAL_API_KEY
    }

    url_id = base64.urlsafe_b64encode(url.encode()).decode().strip("=")
    response = requests.get(f"{api_url}{url_id}", headers=headers)

    if response.status_code == 200:
        data = response.json()
        stats = data.get("data", {}).get("attributes", {}).get("last_analysis_stats", {})
        malicious_count = stats.get("malicious", 0)
        harmless_count = stats.get("harmless", 0)
        undetected_count = stats.get("undetected", 0)
        suspicious_count = stats.get("suspicious", 0)

        return {
            "detected": malicious_count > 0,
            "positives": malicious_count,
            "total": sum(stats.values()),
            "scan_date": data.get("data", {}).get("attributes", {}).get("last_analysis_date", "")
        }
    else:
        print(f"[ERROR] Błąd podczas zapytania do API VirusTotal: {response.status_code}")
        return {
            "detected": False,
            "error": f"Error fetching data from VirusTotal: {response.status_code}"
        }
