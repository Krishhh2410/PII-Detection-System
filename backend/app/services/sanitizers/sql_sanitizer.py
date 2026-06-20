import re
from typing import List
import sqlparse
from sqlparse import tokens as T

from app.services.sanitizers.base import BaseSanitizer
from app.services.pii_detector import PIIDetection


class SQLSanitizer(BaseSanitizer):
    """Sanitizer for SQL dump files."""
    
    def sanitize(self, content: bytes, detections: List[PIIDetection]) -> bytes:
        """
        Sanitize SQL content by replacing PII in string literals.
        Preserves SQL syntax while sanitizing values.
        """
        text = content.decode('utf-8', errors='ignore')
        
        # Sort detections by position (reverse order to avoid offset issues)
        sorted_detections = sorted(detections, key=lambda d: d.start, reverse=True)
        
        # Apply replacements
        for detection in sorted_detections:
            original_text = text[detection.start:detection.end]
            sanitized_text = self.apply_anonymization(original_text, detection)
            
            # Replace in text
            text = text[:detection.start] + sanitized_text + text[detection.end:]
        
        return text.encode('utf-8')
    
    def sanitize_sql_values(self, content: bytes) -> bytes:
        """
        Alternative method: Parse SQL and sanitize values in INSERT statements.
        This is more robust for complex SQL files.
        """
        text = content.decode('utf-8', errors='ignore')
        
        # Pattern to match string literals in SQL
        # Matches single-quoted strings (handles escaped quotes)
        string_pattern = re.compile(r"'(?:[^'\\]|\\.)*'")
        
        def replace_string_literal(match):
            literal = match.group(0)
            # Remove quotes for detection
            inner_text = literal[1:-1]
            
            # Detect PII in the literal
            from app.services.pii_detector import detect_pii
            detections, _ = detect_pii(inner_text)
            
            if detections:
                # Apply sanitization
                sorted_detections = sorted(detections, key=lambda d: d.start, reverse=True)
                sanitized_inner = inner_text
                for detection in sorted_detections:
                    orig = sanitized_inner[detection.start:detection.end]
                    repl = self.apply_anonymization(orig, detection)
                    sanitized_inner = sanitized_inner[:detection.start] + repl + sanitized_inner[detection.end:]
                return "'" + sanitized_inner + "'"
            
            return literal
        
        # Replace all string literals
        sanitized_text = string_pattern.sub(replace_string_literal, text)
        
        return sanitized_text.encode('utf-8')
