# api/utils.py

def load_keywords():
    try:
        with open("data/scam_keywords.txt", "r", encoding="utf-8") as f:
            # Upewnij się, że słowa kluczowe są konwertowane na małe litery
            return [line.strip().lower() for line in f]
    except FileNotFoundError:
        print("Plik 'scam_keywords.txt' nie został znaleziony.")
        return []

def load_numbers():
    with open("data/scam_numbers.txt", "r", encoding="utf-8") as f:
        return [line.strip() for line in f]

def load_domains():
    with open("data/scam_domains.txt", "r", encoding="utf-8") as f:
        return [line.strip().lower() for line in f]

def load_shorteners():
    with open("data/url_shorteners.txt", "r", encoding="utf-8") as f:
        return [line.strip().lower() for line in f]
