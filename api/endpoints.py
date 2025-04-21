# api/endpoints.py
import re
import os
import requests # Still needed for resolve_redirect if in utils
import base64 # Still needed if resolve_redirect uses it
from .utils import load_keywords, load_numbers, load_domains, load_shorteners, resolve_redirect # Assume resolve_redirect is in utils
from .validators import Validators
from transformers import pipeline
import logging # Import logging

logger = logging.getLogger(__name__)

# Importuj funkcję skanującą z osobnego pliku virustotal.py
from .virustotal import scan_url_with_virustotal

# Klucz API VirusTotal NIE jest już potrzebny w endpoints.py,
# ponieważ używa go funkcja w virustotal.py
# VIRUSTOTAL_API_KEY = os.getenv("VT_API_KEY") # <-- Ta linia jest usunięta/zakomentowana

# Inicjalizacja AI modelu
try:
    # Użyj suppress_warnings=True, aby wyciszyć ostrzeżenia przy ładowaniu modelu
    spam_classifier = pipeline("text-classification", model="mrm8488/bert-tiny-finetuned-sms-spam-detection", suppress_warnings=True)
    logger.info("Model AI do detekcji spamu załadowany pomyślnie.")
except Exception as e:
    logger.warning(f"Nie udało się załadować modelu AI: {e}")
    spam_classifier = None

# check_message (pozostaje bez zmian)
def check_message(text: str) -> dict:
    """Sprawdza wiadomość tekstową pod kątem spamu i podejrzanych słów."""
    result = {
        "suspicious_words": [],
        "ai_result": None,
        "is_suspicious": False
    }

    keywords = load_keywords() # Zakładamy, że load_keywords() działa poprawnie
    # Filtruj puste słowa kluczowe po załadowaniu, na wypadek pustych linii w pliku
    keywords = [kw.strip() for kw in keywords if kw.strip()]

    # Sprawdź podejrzane słowa kluczowe (case-insensitive)
    found_keywords = [kw for kw in keywords if kw in text.lower()]
    result["suspicious_words"] = found_keywords

    if spam_classifier:
        try:
            prediction = spam_classifier(text)[0]
            label = prediction["label"]
            confidence = round(prediction["score"], 4)
            result["ai_result"] = {
                "label": "SPAM" if label == "LABEL_1" else "HAM", # Założenie LABEL_1 == SPAM
                "confidence": confidence
            }
            # Warunek podejrzewania uwzględnia słowa LUB AI > 0.6
            result["is_suspicious"] = (label == "LABEL_1" and confidence > 0.6) or bool(result["suspicious_words"])
        except Exception as ai_e:
             logger.error(f"Błąd podczas klasyfikacji AI wiadomości: {ai_e}")
             result["ai_result"] = {"label": "ERROR", "confidence": 0}
             # Jeśli AI zawiodło, podejrzane tylko na podstawie słów
             result["is_suspicious"] = bool(result["suspicious_words"])
    else:
        # Jeśli AI niedostępne, podejrzane tylko na podstawie słów
        result["is_suspicious"] = bool(result["suspicious_words"])

    logger.info(f"Wynik check_message: {result}")
    return result

# check_phone (pozostaje bez zmian)
def check_phone(number: str) -> dict:
    """Sprawdza numer telefonu pod kątem poprawności formatu i listy znanych scamów."""
    known_scams = load_numbers() # Zakładamy, że load_numbers() działa poprawnie
    # Filtruj puste numery po załadowaniu
    known_scams = {num.strip() for num in known_scams if num.strip()}

    is_valid = Validators.is_valid_phone(number) # Zakładamy, że Validators.is_valid_phone() działa poprawnie
    is_suspicious = number in known_scams

    result = {
        "is_valid": is_valid,
        "is_suspicious": is_suspicious
    }
    logger.info(f"Wynik check_phone dla {number}: {result}")
    return result


# check_link (Zmodyfikowany, aby wywołać funkcję z virustotal.py)
def check_link(link: str) -> dict:
    """Sprawdza link pod kątem podejrzanych wzorców, znanych scam domen, skracaczy i skanuje VirusTotal."""
    logger.info(f"Sprawdzam link: {link}")
    # from .utils import resolve_redirect # Już zaimportowane wyżej

    # Rozwiązywanie przekierowań
    # Używamy oryginalnego linku do sprawdzenia skracaczy
    # Ale rozwiązany link do walidacji, analizy lokalnej i VT
    try:
        link_resolved = resolve_redirect(link) # Zakładamy, że resolve_redirect() działa poprawnie
        logger.info(f"Link rozwiązany do: {link_resolved}")
    except Exception as resolve_e:
         logger.error(f"Błąd podczas rozwiązywania linku {link}: {resolve_e}")
         return {
             "is_valid": False,
             "is_suspicious": True, # Uznajemy błąd rozwiązywania za podejrzany
             "details": [{
                 "text": f"Error resolving redirect: {resolve_e}",
                 "data-pl": f"Błąd rozwiązywania przekierowania: {resolve_e}",
                 "data-en": f"Error resolving redirect: {resolve_e}"
             }],
             "source": "local"
         }


    link_clean = link_resolved.lower()

    suspicious_reasons = []

    is_valid = Validators.is_valid_url(link_resolved) # Zakładamy, że Validators.is_valid_url() działa poprawnie
    if not is_valid:
        logger.warning(f"Rozwiązany link nie jest poprawnym URL: {link_resolved}")
        return {
            "is_valid": False,
            "is_suspicious": False, # Jeśli format niepoprawny po rozwiązaniu, nie skanujemy dalej jako "podejrzany scam URL"
            "details": [{
                "text": "Invalid resolved URL format",
                "data-pl": "Niepoprawny format rozwiązanego URL",
                "data-en": "Invalid resolved URL format"
            }],
            "source": "local"
        }

    # Lokalna analiza
    suspicious_patterns = ["free", "gift", "login", "verify", "paypal", "bank", ".ru", ".cn"] # Przykładowe wzorce
    for pattern in suspicious_patterns:
        if pattern in link_clean:
            suspicious_reasons.append({
                "text": f"Suspicious pattern found in URL: {pattern}",
                "data-pl": f"Znaleziono podejrzany wzorzec w URL: {pattern}",
                "data-en": f"Suspicious pattern found in URL: {pattern}"
            })
            logger.info(f"Znaleziono podejrzany wzorzec '{pattern}' w linku: {link_resolved}")


    scam_domains = load_domains() # Zakładamy, że load_domains() działa poprawnie
    # Filtruj puste domeny po załadowaniu
    scam_domains = [domain.strip() for domain in scam_domains if domain.strip()]
    for domain in scam_domains:
        # Sprawdzenie, czy domena scamowa jest podciągiem resolved_link_clean.
        # Bardziej robustne byłoby parsowanie domeny resolved_link i porównanie exact match lub subdomen.
        if domain in link_clean:
            suspicious_reasons.append({
                "text": f"Domain reported as suspicious found in URL: {domain}",
                "data-pl": f"Znaleziona domena zgłoszona jako podejrzana w URL: {domain}",
                "data-en": f"Domain reported as suspicious found in URL: {domain}"
            })
            logger.info(f"Znaleziono podejrzaną domenę '{domain}' w linku: {link_resolved}")


    shorteners = load_shorteners() # Zakładamy, że load_shorteners() działa poprawnie
    # Filtruj puste skracacze po załadowaniu
    shorteners = [short.strip() for short in shorteners if short.strip()]
    is_shortened = False
    for short in shorteners:
        # Sprawdzamy oryginalny link na obecność znanych skracaczy
        if short and short in link.lower():
            is_shortened = True
            suspicious_reasons.append({
                "text": f"Link shortener detected in original link: {short}",
                "data-pl": f"Wykryto skracacz linków w oryginalnym linku: {short}",
                "data-en": f"Link shortener detected in original link: {short}"
            })
            logger.info(f"Wykryto skracacz linków '{short}' w oryginalnym linku: {link}")


    local_is_suspicious = bool(suspicious_reasons)

    # VIRUSTOTAL: Wywołaj skanowanie tylko jeśli lokalna analiza znalazła coś podejrzanego
    # lub jeśli oryginalny link był skrócony.
    vt_result = {"detected": False, "positives": 0, "total": 0, "scan_date": "N/A", "error": "Not scanned locally"} # Domyślny pusty wynik, dodano pole 'error'

    if local_is_suspicious or is_shortened:
        logger.info(f"Lokalna analiza lub skrócony link -> sprawdzam VirusTotal dla: {link_resolved}")
        # Wywołaj funkcję z virustotal.py
        vt_result = scan_url_with_virustotal(link_resolved)
        logger.info(f"Wynik VirusTotal dla {link_resolved}: {vt_result}")


    vt_detected = vt_result.get("detected", False)
    vt_positives = vt_result.get("positives", 0)
    vt_total = vt_result.get("total", 0)
    vt_scan_date = vt_result.get("scan_date", "N/A") # Powinno być już sformatowane na string przez virustotal.py
    vt_error = vt_result.get("error")

    combined_details = []

    # Dodaj powody z analizy lokalnej
    if local_is_suspicious:
        combined_details.extend(suspicious_reasons)

    # Dodaj podsumowanie z VirusTotal, jeśli skanowanie zostało wykonane (lub wystąpił błąd VT)
    # Nie dodajemy podsumowania VT, jeśli nie skanowaliśmy w ogóle
    if 'error' not in vt_result or vt_result.get('error') != "Not scanned locally":
         vt_summary_text = f"VirusTotal: {vt_positives} / {vt_total} silników oznaczyło link."
         vt_summary_pl = f"VirusTotal: {vt_positives} / {vt_total} silników oznaczyło link."
         vt_summary_en = f"VirusTotal: {vt_positives} / {vt_total} engines flagged the link."

         if vt_scan_date and vt_scan_date != "N/A":
              vt_summary_text += f" Data ostatniego skanowania: {vt_scan_date}."
              vt_summary_pl += f" Data ostatniego skanowania: {vt_scan_date}."
              vt_summary_en += f" Scan date: {vt_scan_date}."

         if vt_error:
             vt_summary_text += f" (Błąd VT: {vt_error})"
             vt_summary_pl += f" (Błąd VT: {vt_error})"
             vt_summary_en += f" (VT Error: {vt_error})"


         combined_details.append({
             "text": vt_summary_text,
             "data-pl": vt_summary_pl,
             "data-en": vt_summary_en
         })
    else:
        # Jeśli nie skanowano VT, można dodać informację o pominięciu
         logger.info(f"Pominięto skanowanie VirusTotal dla linku: {link_resolved} (Lokalna analiza czysta i link nieskrócony).")
         # Opcjonalnie można dodać to jako detail, ale zazwyczaj pomijamy
         # combined_details.append({
         #     "text": "VirusTotal scan skipped (local analysis clean and not shortened)",
         #     "data-pl": "Pominięto skanowanie VirusTotal (lokalna analiza czysta i link nieskrócony)",
         #     "data-en": "VirusTotal scan skipped (local analysis clean and not shortened)"
         # })


    # Określenie is_suspicious na podstawie lokalnych i VT wyników
    final_is_suspicious = local_is_suspicious or vt_detected # Link jest podejrzany, jeśli lokalnie znaleziono coś LUB VirusTotal coś wykrył

    # Jeśli nie ma żadnych szczegółów, dodaj informację o braku zagrożeń
    if not combined_details:
         combined_details.append({
             "text": "No suspicious activity detected.",
             "data-pl": "Brak podejrzanej aktywności.",
             "data-en": "No suspicious activity detected."
         })
         source = "none" # Brak detekcji
    elif local_is_suspicious and vt_detected:
         source = "combined"
    elif vt_detected:
         source = "virustotal"
    elif local_is_suspicious:
         source = "local"
    else:
         source = "other" # Np. tylko błąd VT bez lokalnych detekcji? Rzadki przypadek.


    result = {
        "is_valid": True, # Jeśli przeszło walidację formatu na początku
        "is_suspicious": final_is_suspicious,
        "details": combined_details,
        "source": source
    }
    logger.info(f"Wynik check_link dla {link}: {result}")
    return result


# Funkcja check_virustotal została przeniesiona do virustotal.py i nazwana scan_url_with_virustotal
# def check_virustotal(url: str) -> dict:
#     ... (usunięta)