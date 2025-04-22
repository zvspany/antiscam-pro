# api/endpoints.py
import re
import os
import requests
import base64
# Assume load_* and resolve_redirect are in utils.py
from .utils import load_keywords, load_numbers, load_domains, load_shorteners, resolve_redirect
from .validators import Validators
from transformers import pipeline
import logging

logger = logging.getLogger(__name__)

# Importuj funkcję skanującą z osobnego pliku virustotal.py
# Upewnij się, że ten plik i funkcja scan_url_with_virustotal istnieją i działają poprawnie.
from .virustotal import scan_url_with_virustotal

# Klucz API VirusTotal NIE jest potrzebny w endpoints.py,
# ponieważ używa go funkcja w virustotal.py

# Inicjalizacja AI modelu
try:
    # Użyj suppress_warnings=True, aby wyciszyć ostrzeżenia przy ładowaniu modelu
    spam_classifier = pipeline("text-classification", model="mrm8488/bert-tiny-finetuned-sms-spam-detection", suppress_warnings=True)
    logger.info("Model AI do detekcji spamu załadowany pomyślnie.")
except Exception as e:
    logger.warning(f"Nie udało się załadować modelu AI: {e}")
    spam_classifier = None

# check_message - FUNKCJA LOGIKI (POWINNA ZOSTAĆ)
def check_message(text: str) -> dict:
    """Sprawdza wiadomość tekstową pod kątem spamu i podejrzanych słów."""
    result = {
        "suspicious_words": [],
        "ai_result": None,
        "is_suspicious": False
    }

    keywords = load_keywords() # Zakładamy, że load_keywords() działa poprawnie
    # Filtruj puste słowa kluczowe po załadowaniu
    keywords = [kw.strip() for kw in keywords if kw.strip()]

    # Sprawdź podejrzane słowa kluczowe (case-insensitive)
    found_keywords = [kw for kw in keywords if kw.lower() in text.lower()]
    result["suspicious_words"] = found_keywords

    if spam_classifier:
        try:
            # Obetnij wiadomość do pierwszych 512 tokenów, jeśli jest za długa dla modelu BERT
            max_len = 512
            if len(text.split()) > max_len: # Proste sprawdzenie na podstawie słów, lepsze niż nic
                 text_for_ai = " ".join(text.split()[:max_len])
                 logger.warning(f"Wiadomość obcięta do {max_len} słów dla analizy AI.")
            else:
                 text_for_ai = text

            prediction = spam_classifier(text_for_ai)[0]
            label = prediction["label"]
            confidence = round(prediction["score"], 4)
            result["ai_result"] = {
                "label": "SPAM" if label == "LABEL_1" else "HAM", # Założenie LABEL_1 == SPAM
                "confidence": confidence
            }
            # Warunek podejrzewania: AI >= 0.6 LUB znalezione słowa kluczowe
            result["is_suspicious"] = (label == "LABEL_1" and confidence >= 0.6) or bool(result["suspicious_words"])
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

# check_phone - FUNKCJA LOGIKI (POWINNA ZOSTAĆ)
def check_phone(number: str) -> dict:
    """Sprawdza numer telefonu pod kątem poprawności formatu i listy znanych scamów."""
    known_scams = load_numbers() # Zakładamy, że load_numbers() działa poprawnie
    # Filtruj puste numery po załadowaniu
    known_scams = {num.strip() for num in known_scams if num.strip()}

    is_valid = Validators.is_valid_phone(number) # Zakładamy, że Validators.is_valid_phone() działa poprawnie
    # Usuń opcjonalny znak '+' przed sprawdzeniem w bazie, jeśli baza nie zawiera plusów
    number_for_check = number.lstrip('+')
    is_suspicious = number_for_check in known_scams

    result = {
        "is_valid": is_valid,
        "is_suspicious": is_suspicious
    }
    logger.info(f"Wynik check_phone dla {number}: {result}")
    return result


# check_link - FUNKCJA LOGIKI (POWINNA ZOSTAĆ)
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
         # Zwracamy słownik z błędem rozwiązywania przekierowania
         return {
             "is_valid": False,
             "is_suspicious": True, # Uznajemy błąd rozwiązywania za podejrzany
             "details": [{
                 "text": f"Error resolving redirect: {resolve_e}",
                 "data-pl": f"Błąd rozwiązywania przekierowania: {resolve_e}",
                 "data-en": f"Error resolving redirect: {resolve_e}"
             }],
             "source": "local" # Źródłem detekcji jest błąd lokalny
         }

    link_clean = link_resolved.lower()
    suspicious_reasons = []

    is_valid = Validators.is_valid_url(link_resolved) # Zakładamy, że Validators.is_valid_url() działa poprawnie
    if not is_valid:
        logger.warning(f"Rozwiązany link nie jest poprawnym URL: {link_resolved}")
        # Zwracamy słownik informujący o niepoprawnym formacie URL
        return {
            "is_valid": False,
            "is_suspicious": False, # Jeśli format niepoprawny po rozwiązaniu, nie skanujemy dalej jako "podejrzany scam URL", chyba że przekierowanie samo w sobie było podejrzane (co obsłużone jest wyżej)
            "details": [{
                "text": "Invalid resolved URL format",
                "data-pl": "Niepoprawny format rozwiązanego URL",
                "data-en": "Invalid resolved URL format"
            }],
            "source": "local" # Źródłem jest lokalna walidacja formatu
        }

    # Lokalna analiza - wzorce w URL
    suspicious_patterns = ["free", "gift", "login", "verify", "paypal", "paypa1", "bank", ".ru", ".cn"] # Przykładowe wzorce
    for pattern in suspicious_patterns:
        if pattern in link_clean:
            suspicious_reasons.append({
                "text": f"Suspicious pattern found in URL: {pattern}",
                "data-pl": f"Podejrzany wzorzec '{pattern}' znaleziony w adresie URL.", # ZMIENIONO BRZMIENIE
                "data-en": f"Suspicious pattern '{pattern}' found in the URL."
            })
            logger.info(f"Znaleziono podejrzany wzorzec '{pattern}' w linku: {link_resolved}")

    # Lokalna analiza - scam domeny z bazy
    scam_domains = load_domains() # Zakładamy, że load_domains() działa poprawnie
    # Filtruj puste domeny po załadowaniu
    scam_domains = [domain.strip() for domain in scam_domains if domain.strip()]
    # Bardziej robustne byłoby parsowanie domeny resolved_link i porównanie exact match lub subdomen.
    # Poniższa pętla jest uproszczeniem (sprawdza podciąg).
    for domain in scam_domains:
         # Aby sprawdzić, czy scam_domain jest subdomenąresolved_link lub dokładnie pasuje
         # np. 'phish.example.com' in resolved_link_clean, 'example.com' in resolved_link_clean
         # Lepsza metoda:
         # from urllib.parse import urlparse
         # resolved_domain = urlparse(link_resolved).netloc # Pobierz tylko domenę
         # if domain in resolved_domain or resolved_domain.endswith('.' + domain):
         # Poniżej uproszczone sprawdzenie podciągu:
         if domain and domain in link_clean: # Upewnij się, że domena nie jest pusta
            suspicious_reasons.append({
                "text": f"Domain '{domain}' marked as suspicious in our database.",
                "data-pl": f"Domena '{domain}' oznaczona jako podejrzana w naszej bazie danych.", # ZMIENIONO BRZMIENIE
                "data-en": f"Domain '{domain}' marked as suspicious in our database."
            })
            logger.info(f"Znaleziono podejrzaną domenę '{domain}' w linku: {link_resolved}")


    # Lokalna analiza - skracacze linków (sprawdzamy oryginalny link)
    shorteners = load_shorteners() # Zakładamy, że load_shorteners() działa poprawnie
    # Filtruj puste skracacze po załadowaniu
    shorteners = [short.strip() for short in shorteners if short.strip()]
    is_shortened = False
    for short in shorteners:
        # Sprawdzamy oryginalny link na obecność znanych skracaczy
        if short and short in link.lower(): # Upewnij się, że 'short' nie jest puste
            is_shortened = True
            suspicious_reasons.append({
                "text": f"Link shortener detected in original link: {short}",
                "data-pl": f"Wykryto usługę skracania URL w oryginalnym linku: {short}", # ZMIENIONO BRZMIENIE (drobna korekta)
                "data-en": f"Link shortener detected in original link: {short}"
            })
            logger.info(f"Wykryto Usługę skracania URL '{short}' w oryginalnym linku: {link}")


    local_is_suspicious = bool(suspicious_reasons)

    # VIRUSTOTAL: Wywołaj skanowanie tylko jeśli lokalna analiza znalazła coś podejrzanego
    # lub jeśli oryginalny link był skrócony.
    # Inicjalizujemy vt_result domyślnym słownikiem wskazującym na pominięcie skanowania
    vt_result = {"detected": False, "positives": 0, "total": 0, "scan_date": "N/A", "error": "Not scanned locally"}

    # WARUNEK SKANOWANIA VT
    if local_is_suspicious or is_shortened:
        logger.info(f"Lokalna analiza lub skrócony link -> sprawdzam VirusTotal dla: {link_resolved}")
        # Wywołaj funkcję z virustotal.py, która zwraca słownik z wynikami LUB błędem
        vt_result = scan_url_with_virustotal(link_resolved)
        logger.info(f"Wynik VirusTotal dla {link_resolved}: {vt_result}")


    vt_detected = vt_result.get("detected", False)
    vt_positives = vt_result.get("positives", 0)
    vt_total = vt_result.get("total", 0)
    # Scan date should already be a formatted string or "N/A" from virustotal.py
    vt_scan_date = vt_result.get("scan_date", "N/A")
    vt_error = vt_result.get("error") # Błąd API VT lub "Not scanned locally"

    # Budujemy finalną listę szczegółów dla szablonu HTML
    combined_details = []

    # Dodaj powody z analizy lokalnej (jeśli istnieją)
    if local_is_suspicious: # Dodaj lokalne powody tylko jeśli coś wykryto lokalnie
        # Dodajemy nagłówek dla sekcji lokalnych powodów, jeśli chcemy ją oddzielić
        # combined_details.append({"text": "Local Analysis Findings:", "data-pl": "Wyniki analizy lokalnej:", "data-en": "Local Analysis Findings:"})
        combined_details.extend(suspicious_reasons) # Rozszerzamy listę o słowniki z powodami

    # Dodaj podsumowanie z VirusTotal jako JEDEN element listy details, jeśli skanowanie zostało wykonane (lub wystąpił błąd inny niż pominięcie)
    # Warunek sprawdza, czy VT_result to nie jest domyślny stan "Not scanned locally"
    if vt_result.get('error') != "Not scanned locally":
         # Tworzymy string podsumowujący wynik VT
         if vt_error and vt_error != "Not scanned locally": # Jeśli jest błąd VT (inny niż pominięcie)
             vt_summary_text = f"VirusTotal: Error - {vt_error}"
             vt_summary_pl = f"VirusTotal: Błąd - {vt_error}"
             vt_summary_en = f"VirusTotal: Error - {vt_error}"
         else: # Jeśli skanowanie VT zakończyło się sukcesem lub zwróciło brak detekcji/Timeout itp.
             vt_summary_text = f"VirusTotal: {vt_positives} / {vt_total} engines flagged the link."
             vt_summary_pl = f"VirusTotal: {vt_positives} / {vt_total} silników oznaczyło link."
             vt_summary_en = f"VirusTotal: {vt_positives} / {vt_total} engines flagged the link."

             if vt_scan_date and vt_scan_date != "N/A":
                  vt_summary_text += f" Scan date: {vt_scan_date}."
                  vt_summary_pl += f" Data ostatniego skanowania: {vt_scan_date}."
                  vt_summary_en += f" Scan date: {vt_scan_date}."

         # Dodajemy podsumowanie VT jako JEDEN element do listy combined_details
         combined_details.append({
             "text": vt_summary_text,
             "data-pl": vt_summary_pl,
             "data-en": vt_summary_en
         })
    else:
        # Jeśli nie skanowano VT (bo lokalna analiza czysta i link nieskrócony),
        # opcjonalnie możemy dodać informację o pominięciu do details.
        # combined_details.append({
        #     "text": "VirusTotal scan skipped.",
        #     "data-pl": "Skan VirusTotal pominięty (lokalna analiza czysta).",
        #     "data-en": "VirusTotal scan skipped (local analysis clean)."
        # })
        logger.info(f"Pominięto skanowanie VirusTotal dla linku: {link_resolved} (Lokalna analiza czysta i link nieskrócony).")


    # Określenie is_suspicious na podstawie lokalnych i VT wyników
    # Flaga final_is_suspicious jest używana w szablonie do koloru alertu i ogólnego statusu
    final_is_suspicious = local_is_suspicious or vt_detected # Link jest podejrzany, jeśli lokalnie znaleziono coś LUB VirusTotal coś wykrył


    # Jeśli po wszystkich analizach lista combined_details jest pusta, dodaj domyślny komunikat o braku zagrożeń
    # W przeciwnym razie, brak szczegółów sugeruje problem lub niekompletne skanowanie.
    # Upewnij się, że backend zawsze dodaje co najmniej jeden szczegół jeśli link jest przetwarzany.
    # Obecnie, jeśli local_is_suspicious jest False i VT jest pominięte, combined_details będzie puste, co jest ok.
    if not combined_details:
         combined_details.append({
             "text": "No suspicious activity detected based on available checks.",
             "data-pl": "Nie wykryto podejrzanej aktywności na podstawie dostępnych sprawdzeń.",
             "data-en": "No suspicious activity detected based on available checks."
         })
         source = "none" # Brak detekcji
    elif local_is_suspicious and vt_detected:
         source = "combined"
    elif vt_detected:
         source = "virustotal"
    elif local_is_suspicious:
         source = "local"
    else:
         # Ten przypadek nie powinien wystąpić przy obecnej logice, jeśli combined_details nie jest puste.
         # Może oznaczać błąd w logice budowania combined_details.
         source = "unknown"


    result = {
        "is_valid": is_valid, # Czy rozwiązany URL ma poprawny format
        "is_suspicious": final_is_suspicious, # Czy jest podejrzany (lokalnie LUB VT)
        "details": combined_details, # Lista słowników z powodami/podsumowaniami
        "source": source # Źródło głównej detekcji (lub 'none'/'unknown')
    }
    logger.info(f"Final result for check_link ({link}): {result}")
    return result


# check_virustotal - FUNKCJA LOGIKI (POWINNA BYĆ W virustotal.py)
# Ta funkcja powinna być w virustotal.py i stamtąd importowana do endpoints.py
# Usuwam ją stąd, jeśli tam się znajduje
# def scan_url_with_virustotal(url: str) -> dict:
#     ... (Ta funkcja powinna być w virustotal.py)

# API ENDPOINTS - PRZENIESIONE DO app.py
# Usunięte z tego pliku, ponieważ powinny być w app.py

# @app.route("/api/check_message", methods=["POST"])
# def api_check_message():
#     ... (usunięte)

# @app.route("/api/check_phone", methods=["POST"])
# def api_check_phone():
#     ... (usunięte)

# @app.route("/api/check_link", methods=["POST"])
# def api_check_link():
#     ... (usunięte)