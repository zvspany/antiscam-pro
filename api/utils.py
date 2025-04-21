# api/utils.py

import requests

def load_keywords():
    try:
        with open("data/scam_keywords.txt", "r", encoding="utf-8") as f:
            # Upewnij się, że słowa kluczowe są konwertowane na małe litery
            return [line.strip().lower() for line in f]
    except FileNotFoundError:
        print("Plik 'scam_keywords.txt' nie został znaleziony.")
        return []

def load_numbers():
    try:
        with open("data/scam_numbers.txt", "r", encoding="utf-8") as f:
            return [line.strip() for line in f]
    except FileNotFoundError:
        print("Plik 'scam_numbers.txt' nie został znaleziony.")
        return []

def load_domains():
    try:
        with open("data/scam_domains.txt", "r", encoding="utf-8") as f:
            return [line.strip().lower() for line in f]
    except FileNotFoundError:
        print("Plik 'scam_domains.txt' nie został znaleziony.")
        return []

def load_shorteners():
    try:
        with open("data/url_shorteners.txt", "r", encoding="utf-8") as f:
            return [line.strip().lower() for line in f]
    except FileNotFoundError:
        print("Plik 'url_shorteners.txt' nie został znaleziony.")
        return []

def resolve_redirect(url: str) -> str:
    """
    Rozwiązuje przekierowania w linkach skracających typu bit.ly itd.
    Zwraca finalny URL lub oryginalny, jeśli nie uda się przekierować.
    """
    try:
        response = requests.head(url, allow_redirects=True, timeout=5)
        return response.url
    except Exception as e:
        print(f"[WARN] Nie udało się rozwiązać przekierowania: {e}")
        return url
