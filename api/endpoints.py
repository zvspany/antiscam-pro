import re

def load_keywords():
    with open("data/scam_keywords.txt", "r", encoding="utf-8") as f:
        return [line.strip().lower() for line in f]

def load_numbers():
    with open("data/scam_numbers.txt", "r") as f:
        return [line.strip() for line in f]

def check_message(text):
    keywords = load_keywords()
    found = [kw for kw in keywords if kw in text.lower()]
    return {"suspicious_words": found, "is_suspicious": bool(found)}

def check_phone(number):
    numbers = load_numbers()
    return {"is_suspicious": number in numbers}

def check_link(link):
    patterns = ["free", "gift", "login", "verify", "paypal", "bank", ".ru", ".cn"]
    found = [pat for pat in patterns if pat in link.lower()]
    return {"suspicious_patterns": found, "is_suspicious": bool(found)}