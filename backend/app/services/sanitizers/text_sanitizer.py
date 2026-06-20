"""Text sanitizer for plain text files."""
from app.services.sanitizers.base import BaseSanitizer


class TextSanitizer(BaseSanitizer):
    """Sanitizer for plain text files."""
    
    def sanitize(self, content: bytes, detections: list) -> bytes:
        """
        Sanitize text content by applying anonymization to detected PII.
        
        Args:
            content: Original text content as bytes
            detections: List of detected PII entities
            
        Returns:
            Sanitized content as bytes
        """
        text = content.decode('utf-8', errors='ignore')
        
        # Sort detections by position (reverse order to avoid offset issues)
        sorted_detections = sorted(detections, key=lambda d: d.start, reverse=True)
        
        for detection in sorted_detections:
            original_text = text[detection.start:detection.end]
            sanitized_text = self.apply_anonymization(original_text, detection)
            text = text[:detection.start] + sanitized_text + text[detection.end:]
        
        return text.encode('utf-8')
