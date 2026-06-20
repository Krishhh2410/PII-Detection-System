import pytest
from app.services.pii_detector import (
    RegexDetectors, 
    PIIDetectionEngine, 
    detect_pii,
    PIIDetection
)


class TestRegexDetectors:
    """Test regex-based PII detectors."""
    
    def test_detect_email(self):
        """Test email detection."""
        text = "Contact me at john.doe@example.com or jane@company.co.uk"
        matches = RegexDetectors.detect_emails(text)
        
        assert len(matches) == 2
        assert matches[0][2] == "john.doe@example.com"
        assert matches[1][2] == "jane@company.co.uk"
    
    def test_detect_phone_india(self):
        """Test Indian phone number detection."""
        text = "Call me at +91-9876543210 or 09876543210 or +91 87654 32109"
        matches = RegexDetectors.detect_phones(text)
        
        assert len(matches) >= 2
        phone_numbers = [m[2] for m in matches]
        assert any("9876543210" in p for p in phone_numbers)
    
    def test_detect_aadhaar(self):
        """Test Aadhaar number detection."""
        text = "My Aadhaar is 1234 5678 9012 or 987654321098"
        matches = RegexDetectors.detect_aadhaar(text)
        
        assert len(matches) == 2
        aadhaars = [m[2] for m in matches]
        assert "1234 5678 9012" in aadhaars
        assert "987654321098" in aadhaars
    
    def test_detect_pan(self):
        """Test PAN number detection."""
        text = "PAN: ABCDE1234F and XYZAB5678C"
        matches = RegexDetectors.detect_pan(text)
        
        assert len(matches) == 2
        pans = [m[2] for m in matches]
        assert "ABCDE1234F" in pans
        assert "XYZAB5678C" in pans
    
    def test_detect_ip_address(self):
        """Test IP address detection."""
        text = "Server at 192.168.1.100 and backup at 10.0.0.50"
        matches = RegexDetectors.detect_ip_addresses(text)
        
        assert len(matches) == 2
        ips = [m[2] for m in matches]
        assert "192.168.1.100" in ips
        assert "10.0.0.50" in ips
    
    def test_detect_credit_card(self):
        """Test credit card detection."""
        text = "Card: 4532-1234-5678-9012 or 4111111111111111"
        matches = RegexDetectors.detect_credit_cards(text)
        
        assert len(matches) >= 1
        cards = [m[2] for m in matches]
        assert any("4532" in c for c in cards)


class TestPIIDetectionEngine:
    """Test the main PII detection engine."""
    
    def test_detect_all_entities(self):
        """Test detection of all entity types."""
        text = """
        Employee: Rajesh Kumar
        Email: rajesh.kumar@techcorp.in
        Phone: +91-9876543210
        Aadhaar: 1234 5678 9012
        PAN: ABCDE1234F
        Address: 123 MG Road, Bangalore
        IP: 192.168.1.100
        DOB: 15/03/1985
        """
        
        engine = PIIDetectionEngine()
        detections = engine.detect_all(text)
        
        entity_types = [d.entity_type for d in detections]
        
        assert "EMAIL" in entity_types
        assert "PHONE" in entity_types
        assert "AADHAAR" in entity_types
        assert "PAN" in entity_types
        assert "IP_ADDRESS" in entity_types
    
    def test_entity_counts(self):
        """Test entity counting."""
        text = """
        Contact: john@example.com, jane@example.com
        Phones: +91-9876543210, +91-8765432109
        """
        
        engine = PIIDetectionEngine()
        detections = engine.detect_all(text)
        counts = engine.get_entity_counts(detections)
        
        assert counts.get("EMAIL", 0) == 2
        assert counts.get("PHONE", 0) >= 2
    
    def test_merge_overlapping_detections(self):
        """Test that overlapping detections are merged."""
        # Create overlapping detections
        detections = [
            PIIDetection("EMAIL", 0, 10, "test@test.com", 0.9, "regex"),
            PIIDetection("EMAIL", 0, 10, "test@test.com", 0.8, "ner"),
        ]
        
        engine = PIIDetectionEngine()
        merged = engine._merge_detections(detections)
        
        # Should merge to single detection
        assert len(merged) == 1
    
    def test_detect_pii_convenience_function(self):
        """Test the convenience function."""
        text = "Email: user@example.com, Phone: 9876543210"
        
        detections, counts = detect_pii(text)
        
        assert len(detections) >= 2
        assert "EMAIL" in counts
        assert "PHONE" in counts


class TestDetectionConfidence:
    """Test detection confidence scores."""
    
    def test_email_confidence(self):
        """Test email detection has high confidence."""
        text = "Contact: test@example.com"
        detections, _ = detect_pii(text)
        
        email_detections = [d for d in detections if d.entity_type == "EMAIL"]
        assert len(email_detections) == 1
        assert email_detections[0].confidence >= 0.9
    
    def test_aadhaar_confidence(self):
        """Test Aadhaar detection has high confidence."""
        text = "Aadhaar: 1234 5678 9012"
        detections, _ = detect_pii(text)
        
        aadhaar_detections = [d for d in detections if d.entity_type == "AADHAAR"]
        assert len(aadhaar_detections) == 1
        assert aadhaar_detections[0].confidence >= 0.95


class TestEdgeCases:
    """Test edge cases and special scenarios."""
    
    def test_empty_text(self):
        """Test detection on empty text."""
        detections, counts = detect_pii("")
        assert len(detections) == 0
        assert len(counts) == 0
    
    def test_no_pii(self):
        """Test text with no PII."""
        text = "This is a normal document with no sensitive information."
        detections, counts = detect_pii(text)
        assert len(detections) == 0
    
    def test_multiple_same_type(self):
        """Test multiple entities of same type."""
        text = "Emails: a@test.com, b@test.com, c@test.com"
        detections, counts = detect_pii(text)
        
        assert counts.get("EMAIL", 0) == 3
    
    def test_international_phone_formats(self):
        """Test various international phone formats."""
        text = """
        India: +91-9876543210
        US: +1-555-123-4567
        UK: +44 20 7946 0958
        """
        matches = RegexDetectors.detect_phones(text)
        
        # Should detect at least the Indian number
        assert len(matches) >= 1
