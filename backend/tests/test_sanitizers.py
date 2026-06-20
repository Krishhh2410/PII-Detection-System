import pytest
from app.services.pii_detector import PIIDetection
from app.services.sanitizers.base import BaseSanitizer


class MockSanitizer(BaseSanitizer):
    """Concrete sanitizer for testing."""
    
    def sanitize(self, content: bytes, detections: list) -> bytes:
        return content


class TestBaseSanitizer:
    """Test base sanitizer functionality."""
    
    def test_mask_email(self):
        """Test email masking."""
        sanitizer = MockSanitizer(mode="mask")
        detection = PIIDetection("EMAIL", 0, 20, "john.doe@example.com", 0.9, "regex")
        
        result = sanitizer.apply_anonymization("john.doe@example.com", detection)
        assert result == "j***@example.com"
    
    def test_mask_phone(self):
        """Test phone masking."""
        sanitizer = MockSanitizer(mode="mask")
        detection = PIIDetection("PHONE", 0, 10, "9876543210", 0.9, "regex")
        
        result = sanitizer.apply_anonymization("9876543210", detection)
        assert result.endswith("3210")
        assert result.startswith("******")
    
    def test_mask_aadhaar(self):
        """Test Aadhaar masking."""
        sanitizer = MockSanitizer(mode="mask")
        detection = PIIDetection("AADHAAR", 0, 14, "1234 5678 9012", 0.9, "regex")
        
        result = sanitizer.apply_anonymization("1234 5678 9012", detection)
        assert result.endswith("9012")
        assert result.startswith("********")
    
    def test_mask_pan(self):
        """Test PAN masking."""
        sanitizer = MockSanitizer(mode="mask")
        detection = PIIDetection("PAN", 0, 10, "ABCDE1234F", 0.9, "regex")
        
        result = sanitizer.apply_anonymization("ABCDE1234F", detection)
        assert result.startswith("AB")
        assert result.endswith("F")
        assert "******" in result
    
    def test_mask_ip_address(self):
        """Test IP address masking."""
        sanitizer = MockSanitizer(mode="mask")
        detection = PIIDetection("IP_ADDRESS", 0, 13, "192.168.1.100", 0.9, "regex")
        
        result = sanitizer.apply_anonymization("192.168.1.100", detection)
        assert result.startswith("192")
        assert "***" in result
    
    def test_redact_mode(self):
        """Test redaction mode."""
        sanitizer = MockSanitizer(mode="redact")
        detection = PIIDetection("EMAIL", 0, 20, "test@example.com", 0.9, "regex")
        
        result = sanitizer.apply_anonymization("test@example.com", detection)
        assert result == "[REDACTED_EMAIL]"
    
    def test_tokenize_mode(self):
        """Test tokenization mode."""
        sanitizer = MockSanitizer(mode="tokenize")
        detection = PIIDetection("EMAIL", 0, 20, "test@example.com", 0.9, "regex")
        
        result = sanitizer.apply_anonymization("test@example.com", detection)
        assert result.startswith("[TOK_")
        assert result.endswith("]")
    
    def test_mask_credit_card(self):
        """Test credit card masking."""
        sanitizer = MockSanitizer(mode="mask")
        detection = PIIDetection("CREDIT_CARD", 0, 19, "4532-1234-5678-9012", 0.9, "regex")
        
        result = sanitizer.apply_anonymization("4532-1234-5678-9012", detection)
        assert result.endswith("9012")
        assert "****" in result
    
    def test_mask_person_name(self):
        """Test person name masking."""
        sanitizer = MockSanitizer(mode="mask")
        detection = PIIDetection("PERSON_NAME", 0, 12, "John Smith", 0.9, "ner")
        
        result = sanitizer.apply_anonymization("John Smith", detection)
        assert "J***" in result
        assert "S****" in result


class TestSanitizationModes:
    """Test different sanitization modes."""
    
    def test_same_value_same_token(self):
        """Test that same value gets same token."""
        sanitizer = MockSanitizer(mode="tokenize")
        detection = PIIDetection("EMAIL", 0, 20, "test@example.com", 0.9, "regex")
        
        result1 = sanitizer.apply_anonymization("test@example.com", detection)
        result2 = sanitizer.apply_anonymization("test@example.com", detection)
        
        # Same value should produce same token
        assert result1 == result2
    
    def test_different_value_different_token(self):
        """Test that different values get different tokens."""
        sanitizer = MockSanitizer(mode="tokenize")
        detection1 = PIIDetection("EMAIL", 0, 20, "a@test.com", 0.9, "regex")
        detection2 = PIIDetection("EMAIL", 0, 20, "b@test.com", 0.9, "regex")
        
        result1 = sanitizer.apply_anonymization("a@test.com", detection1)
        result2 = sanitizer.apply_anonymization("b@test.com", detection2)
        
        # Different values should produce different tokens
        assert result1 != result2


class TestSanitizationEdgeCases:
    """Test edge cases in sanitization."""
    
    def test_empty_text(self):
        """Test sanitization of empty text."""
        sanitizer = MockSanitizer(mode="mask")
        detection = PIIDetection("EMAIL", 0, 0, "", 0.9, "regex")
        
        result = sanitizer.apply_anonymization("", detection)
        assert result == "***"
    
    def test_short_email(self):
        """Test masking of short email."""
        sanitizer = MockSanitizer(mode="mask")
        detection = PIIDetection("EMAIL", 0, 8, "a@b.com", 0.9, "regex")
        
        result = sanitizer.apply_anonymization("a@b.com", detection)
        assert "@" in result
    
    def test_short_phone(self):
        """Test masking of short phone number."""
        sanitizer = MockSanitizer(mode="mask")
        detection = PIIDetection("PHONE", 0, 3, "123", 0.9, "regex")
        
        result = sanitizer.apply_anonymization("123", detection)
        assert result == "***"
