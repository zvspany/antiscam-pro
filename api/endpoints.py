import re
from .utils import load_keywords, load_numbers, load_domains, load_shorteners
from .validators import Validators
from transformers import pipeline

# Inicjalizacja modelu AI do klasyfikacji wiadomości SMS
try:
    spam_classifier = pipeline("text-classification", model="mrm8488/bert-tiny-finetuned-sms-spam-detection")
except Exception as e:
    print(f"[WARN] Nie udało się załadować modelu AI: {e}")
    spam_classifier = None

def check_message(text: str) -> dict:
    """
    Analizuje wiadomość pod kątem słów kluczowych i potencjalnego spamu
    przy użyciu modelu AI (jeśli dostępny).

    Returns:
        dict: {
            suspicious_words: list[str],
            ai_result: Optional[dict],
            is_suspicious: bool
        }
    """
    result = {
        "suspicious_words": [],
        "ai_result": None,
        "is_suspicious": False
    }

    # Załaduj słowa kluczowe
    keywords = load_keywords()

    # Debugowanie: Sprawdzenie, czy lista słów kluczowych została załadowana
    if not keywords:
        print("Brak załadowanych słów kluczowych.")
    else:
        print(f"Załadowane słowa kluczowe: {keywords[:10]}...")

    # Upewnij się, że text jest odpowiednio przekazywany i sprawdzany
    print(f"Sprawdzana wiadomość: {text}")

    # Porównanie słów kluczowych z wiadomością
    result["suspicious_words"] = [kw for kw in keywords if kw in text.lower()]

    # Debugowanie: Sprawdzenie wyników porównania
    print(f"Podejrzane słowa: {result['suspicious_words']}")

    # AI analiza (jeśli dostępna)
    if spam_classifier:
        prediction = spam_classifier(text)[0]
        label = prediction["label"]  # 'LABEL_1' = spam
        confidence = round(prediction["score"], 4)
        result["ai_result"] = {
            "label": "SPAM" if label == "LABEL_1" else "HAM",
            "confidence": confidence
        }

        # Uwaga: teraz AI i słowa kluczowe są brane pod uwagę razem
        result["is_suspicious"] = (label == "LABEL_1") or bool(result["suspicious_words"])
    else:
        result["is_suspicious"] = bool(result["suspicious_words"])

    # Debug: co zostanie zwrócone
    print(f"Wynik analizy wiadomości: {result}")

    return result




    # Słowa kluczowe (lokalne heurystyki)
    keywords = load_keywords()
    result["suspicious_words"] = [kw for kw in keywords if kw in text.lower()]

    # AI analiza (jeśli dostępna)
    if spam_classifier:
        prediction = spam_classifier(text)[0]
        label = prediction["label"]  # 'LABEL_1' = spam
        confidence = round(prediction["score"], 4)
        result["ai_result"] = {"label": "SPAM" if label == "LABEL_1" else "HAM", "confidence": confidence}
        result["is_suspicious"] = label == "LABEL_1"
    else:
        result["is_suspicious"] = bool(result["suspicious_words"])

    return result

def check_phone(number: str) -> dict:
    """
    Sprawdza numer telefonu:
    - Waliduje jego format
    - Porównuje z listą znanych scamowych numerów

    Returns:
        dict: {
            is_valid: bool,
            is_suspicious: bool
        }
    """
    known_scams = load_numbers()
    return {
        "is_valid": Validators.is_valid_phone(number),
        "is_suspicious": number in known_scams
    }

def load_shorteners() -> list:
    """
    Ładuje listę skracaczy URL z pliku data/url_shorteners.txt
    """
    try:
        with open("data/url_shorteners.txt", "r") as file:
            return [line.strip().lower() for line in file.readlines()]
    except FileNotFoundError:
        print("Plik data/url_shorteners.txt nie został znaleziony.")
        return []


def check_link(link: str) -> dict:
    """
    Sprawdza link pod kątem:
    - Podejrzanych wzorców (np. "free", "gift", "login")
    - Obecności oszukańczych domen
    - Skracaczy linków

    Returns:
        dict: {
            "is_valid": bool,
            "is_suspicious": bool,
            "suspicious_words": list[str]
        }
    """
    # Początkowa lista powodów
    suspicious_reasons = []
    link_clean = link.lower()  # Zamiana na małe litery w celu porównania

    print(f"Sprawdzanie linku: {link_clean}")

    # Walidacja URL
    is_valid = Validators.is_valid_url(link)
    print(f"Link jest {'poprawny' if is_valid else 'niepoprawny'}")

    if not is_valid:
        # Jeśli link nie jest poprawny, zwracamy odpowiedni komunikat
        return {
            "is_valid": False,
            "is_suspicious": False,
            "suspicious_words": ["Niepoprawny format linku"]
        }

    # Sprawdzenie podejrzanych wzorców
    suspicious_patterns = ["free", "gift", "login", "verify", "paypal", "bank", ".ru", ".cn"]
    for pattern in suspicious_patterns:
        if pattern in link_clean:
            suspicious_reasons.append(f"Podejrzany wzorzec: {pattern}")

    # Sprawdzenie domen oszukańczych
    scam_domains = load_domains()
    print(f"Ładowanie domen oszukańczych: {scam_domains}")
    for domain in scam_domains:
        if domain in link_clean:
            suspicious_reasons.append(f"Oszukańcza domena: {domain}")

    # Sprawdzenie skracaczy URL
    shorteners = load_shorteners()
    print(f"Ładowanie skracaczy URL: {shorteners}")
    for short in shorteners:
        if short in link_clean:
            suspicious_reasons.append(f"Skrócony link: {short}")

    # Zwracamy wynik
    print(f"Powody podejrzeń: {suspicious_reasons}")
    
    return {
        "is_valid": True,
        "is_suspicious": bool(suspicious_reasons),  # Jeśli są jakieś powody, link jest podejrzany
        "suspicious_words": suspicious_reasons
    }
