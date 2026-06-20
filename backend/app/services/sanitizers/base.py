from abc import ABC, abstractmethod
from typing import List


class BaseSanitizer(ABC):
    """Base class for all sanitizers."""
    
    def __init__(self, mode: str = "mask"):
        """
        Initialize sanitizer.
        
        Args:
            mode: Sanitization mode - 'mask', 'redact', or 'tokenize'
        """
        self.mode = mode
    
    @abstractmethod
    def sanitize(self, content: bytes, detections: List) -> bytes:
        """
        Sanitize content by applying anonymization to detected PII.
        
        Args:
            content: Original file content
            detections: List of detected PII entities
            
        Returns:
            Sanitized content as bytes
        """
        pass
    
    def apply_anonymization(self, text: str, detection) -> str:
        """
        Apply anonymization to a single PII detection.
        
        Args:
            text: The detected PII text
            detection: The PII detection object
            
        Returns:
            Anonymized text
        """
        if self.mode == "redact":
            return self._redact(text, detection)
        elif self.mode == "tokenize":
            return self._tokenize(text, detection)
        else:  # mask
            return self._mask(text, detection)
    
    def _mask(self, text: str, detection) -> str:
        """Mask the PII with partial replacement."""
        entity_type = detection.entity_type
        
        if entity_type == "EMAIL":
            # j***@gmail.com
            if "@" in text:
                local, domain = text.split("@", 1)
                if len(local) > 1:
                    return local[0] + "***@" + domain
                return "***@" + domain
            return "***"
        
        elif entity_type == "PHONE":
            # ******1234 (keep last 4)
            digits = ''.join(c for c in text if c.isdigit())
            if len(digits) >= 4:
                return "*" * (len(digits) - 4) + digits[-4:]
            return "*" * len(digits)
        
        elif entity_type == "AADHAAR":
            # ********1234 (keep last 4)
            digits = ''.join(c for c in text if c.isdigit())
            if len(digits) == 12:
                return "********" + digits[-4:]
            return "*" * len(digits)
        
        elif entity_type == "PAN":
            # AB******C (keep first 2 and last 1)
            if len(text) >= 3:
                return text[:2] + "******" + text[-1]
            return "***"
        
        elif entity_type == "IP_ADDRESS":
            # 192.***.***.***
            parts = text.split(".")
            if len(parts) == 4:
                return parts[0] + ".***.***.***"
            return "***.***.***.***"
        
        elif entity_type == "CREDIT_CARD":
            # ****-****-****-1234
            digits = ''.join(c for c in text if c.isdigit())
            if len(digits) >= 4:
                return "****-****-****-" + digits[-4:]
            return "****-****-****-****"
        
        elif entity_type == "PERSON_NAME":
            # J*** Doe
            parts = text.split()
            masked_parts = []
            for part in parts:
                if len(part) > 1:
                    masked_parts.append(part[0] + "*" * (len(part) - 1))
                else:
                    masked_parts.append("*")
            return " ".join(masked_parts)
        
        elif entity_type == "DOB":
            # ** March ****
            # Mask day and year, keep month
            parts = text.split()
            if len(parts) >= 3:
                return "** " + parts[1] + " ****"
            return "**/**/****"
        
        elif entity_type == "PASSPORT":
            # A******* (keep first letter)
            if len(text) >= 1:
                return text[0] + "*" * (len(text) - 1)
            return "********"
        
        elif entity_type == "BANK_ACCOUNT":
            # **********7890 (keep last 4)
            if len(text) >= 4:
                return "*" * (len(text) - 4) + text[-4:]
            return "*" * len(text)
        
        elif entity_type == "IFSC":
            # HDFC0****** (keep first 5 chars)
            if len(text) >= 5:
                return text[:5] + "*" * (len(text) - 5)
            return "*" * len(text)
        
        elif entity_type == "UPI":
            # aa****@upi
            if "@" in text:
                local, domain = text.split("@", 1)
                if len(local) > 2:
                    return local[:2] + "****" + "@" + domain
                return "****@" + domain
            return "****"
        
        elif entity_type == "DEVICE_ID":
            # android-********
            parts = text.split("-")
            if len(parts) >= 2:
                return parts[0] + "-" + "*" * len("-".join(parts[1:]))
            return "****"
        
        elif entity_type in ["FINGERPRINT", "FACE_TEMPLATE"]:
            # fp_hash_************
            parts = text.split("_")
            if len(parts) >= 2:
                return "_".join(parts[:-1]) + "_" + "*" * len(parts[-1])
            return "****"
        
        elif entity_type == "ADDRESS":
            # Mask address: keep first few chars of each word, mask the rest
            # "123 Main Street, City 123456" -> "1** M*** S*****, C*** 1*****"
            words = text.split()
            masked_words = []
            for word in words:
                # Check if word is a number (like house number or PIN)
                if word.isdigit():
                    if len(word) == 6:  # PIN code
                        masked_words.append(word[:1] + "*****")
                    else:
                        masked_words.append(word[:1] + "*" * (len(word) - 1))
                elif len(word) > 3:
                    # Keep first 1-2 chars, mask rest
                    keep = 1 if len(word) <= 5 else 2
                    masked_words.append(word[:keep] + "*" * (len(word) - keep))
                else:
                    masked_words.append("*" * len(word))
            return " ".join(masked_words)
        
        else:
            # Default: mask middle portion
            if len(text) > 4:
                return text[:2] + "***" + text[-2:]
            return "***"
    
    def _redact(self, text: str, detection) -> str:
        """Redact the PII completely."""
        return f"[REDACTED_{detection.entity_type}]"
    
    def _tokenize(self, text: str, detection) -> str:
        """Replace with a stable token."""
        from app.utils.security import generate_token
        token = generate_token(text)
        return f"[{token}]"
