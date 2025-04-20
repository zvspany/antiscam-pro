import re
from typing import Optional

class Validators:
    @staticmethod
    def is_valid_phone(number: str) -> bool:
        """
        Validate phone number format (E.164 with optional +)
        Allowed formats:
        +48123456789
        48123456789
        123456789
        """
        return re.match(r"^\+?\d{9,15}$", number) is not None

    @staticmethod
    def is_valid_email(email: str) -> bool:
        """
        Validate email format
        """
        return re.match(r"^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$", email) is not None

    @staticmethod
    def is_valid_password(password: str, min_length: int = 8) -> bool:
        """
        Validate password:
        - Minimum length
        - At least one digit
        - At least one uppercase
        - At least one lowercase
        """
        if len(password) < min_length:
            return False
        if not re.search(r"\d", password):
            return False
        if not re.search(r"[A-Z]", password):
            return False
        if not re.search(r"[a-z]", password):
            return False
        return True

    @staticmethod
    def is_valid_username(username: str, min_length: int = 3, max_length: int = 20) -> bool:
        """
        Validate username:
        - Only alphanumeric and underscores
        - Length between min and max
        """
        return (re.match(r"^[a-zA-Z0-9_]+$", username) is not None and
                min_length <= len(username) <= max_length)

    @staticmethod
    def is_valid_postal_code(code: str, country: str = 'PL') -> bool:
        """
        Validate postal code format for different countries
        Default: Polish format (00-000)
        """
        if country == 'PL':
            return re.match(r"^\d{2}-\d{3}$", code) is not None
        # Add other country formats as needed
        return False

    @staticmethod
    def is_valid_url(url: str) -> bool:
        """
        Validate URL format
        """
        return re.match(
            r"^(https?://)?(www\.)?[a-z0-9-]+(\.[a-z]{2,}){1,}(/.*)?$", 
            url, 
            re.IGNORECASE
        ) is not None

    @staticmethod
    def is_length_valid(text: str, min_len: int = 0, max_len: Optional[int] = None) -> bool:
        """
        Validate text length
        """
        if max_len is None:
            return len(text) >= min_len
        return min_len <= len(text) <= max_len

    @staticmethod
    def is_numeric(text: str) -> bool:
        """
        Check if text contains only digits
        """
        return text.isdigit()

    @staticmethod
    def is_alpha(text: str) -> bool:
        """
        Check if text contains only letters
        """
        return text.isalpha()

    @staticmethod
    def is_alphanumeric(text: str) -> bool:
        """
        Check if text contains only letters and digits
        """
        return text.isalnum()
