import re
import json
from typing import List, Dict, Tuple, Optional
from dataclasses import dataclass, asdict
from collections import defaultdict

try:
    import spacy
    SPACY_AVAILABLE = True
except ImportError:
    SPACY_AVAILABLE = False


@dataclass
class PIIDetection:
    """Represents a detected PII entity."""
    entity_type: str
    start: int
    end: int
    text: str
    confidence: float
    detection_method: str  # 'regex' or 'ner'
    
    def to_dict(self):
        return asdict(self)


class RegexDetectors:
    """Regex-based PII detectors."""
    
    # Email pattern (RFC-lite)
    EMAIL_PATTERN = re.compile(
        r'\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Z|a-z]{2,}\b'
    )
    
    # Phone patterns (India-focused + generic)
    PHONE_PATTERNS = [
        # Indian mobile: +91-XXXXXXXXXX, 91XXXXXXXXXX, 0XXXXXXXXXX, XXXXXXXXXX
        re.compile(r'(?:\+91[-\s]?)?(?:91[-\s]?)?(?:0)?[6-9]\d{9}\b'),
        # Indian format with spaces: +91 XXXX XXXX XX
        re.compile(r'\+91[-\s]?\d{5}[-\s]?\d{5}'),
        # Generic international
        re.compile(r'\+\d{1,3}[-\s]?\d{3,14}'),
    ]
    
    # Aadhaar: 12 digits, with or without spaces
    AADHAAR_PATTERN = re.compile(
        r'\b\d{4}\s?\d{4}\s?\d{4}\b'
    )
    
    # PAN: ABCDE1234F
    PAN_PATTERN = re.compile(
        r'\b[A-Z]{5}[0-9]{4}[A-Z]\b'
    )
    
    # IP Address: IPv4
    IP_PATTERN = re.compile(
        r'\b(?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\b'
    )
    
    # Credit Card (basic pattern)
    CREDIT_CARD_PATTERN = re.compile(
        r'\b(?:\d{4}[-\s]?){3}\d{4}\b'
    )
    
    # Date of Birth patterns
    DOB_PATTERNS = [
        re.compile(r'\b\d{2}[/-]\d{2}[/-]\d{4}\b'),  # DD/MM/YYYY or DD-MM-YYYY
        re.compile(r'\b\d{4}[/-]\d{2}[/-]\d{2}\b'),  # YYYY/MM/DD or YYYY-MM-DD
        re.compile(r'\b\d{1,2}\s+(?:January|February|March|April|May|June|July|August|September|October|November|December|Jan|Feb|Mar|Apr|May|Jun|Jul|Aug|Sep|Oct|Nov|Dec)\s+\d{4}\b', re.IGNORECASE),  # 14 March 1992
    ]
    
    # Passport: Alphanumeric, typically 8 characters
    PASSPORT_PATTERN = re.compile(
        r'\b[A-Z]\d{7,8}\b'
    )
    
    # Bank Account: 9-18 digits
    BANK_ACCOUNT_PATTERN = re.compile(
        r'\b\d{9,18}\b'
    )
    
    # IFSC Code: 4 letters + 0 + 6 alphanumeric
    IFSC_PATTERN = re.compile(
        r'\b[A-Z]{4}0[A-Z0-9]{6}\b'
    )
    
    # UPI ID: username@bank or username@upi
    UPI_PATTERN = re.compile(
        r'\b[A-Za-z0-9._-]+@[A-Za-z0-9._-]+\b'
    )
    
    # Device ID: Various patterns
    DEVICE_ID_PATTERN = re.compile(
        r'\b(?:android|ios)-[a-f0-9]+\b',
        re.IGNORECASE
    )
    
    # Biometric patterns
    FINGERPRINT_PATTERN = re.compile(
        r'\bfp_hash_[a-f0-9]+\b',
        re.IGNORECASE
    )
    
    FACE_TEMPLATE_PATTERN = re.compile(
        r'\bface_tmp_[a-f0-9]+\b',
        re.IGNORECASE
    )
    
    # Address patterns
    # Indian PIN code pattern
    PINCODE_PATTERN = re.compile(
        r'\b[1-9][0-9]{5}\b'
    )
    
    # Common street address indicators
    ADDRESS_KEYWORDS = re.compile(
        r'\b(?:house|flat|apt|apartment|street|st|road|rd|lane|ln|avenue|ave|'
        r'boulevard|blvd|drive|dr|circle|cir|building|bldg|floor|fl|'
        r'block|blk|sector|near|beside|opposite|behind|in front of|'
        r'village|town|city|district|state|country|pin|zip|postal)\b',
        re.IGNORECASE
    )
    
    @classmethod
    def detect_emails(cls, text: str) -> List[Tuple[int, int, str]]:
        """Detect email addresses."""
        matches = []
        for match in cls.EMAIL_PATTERN.finditer(text):
            matches.append((match.start(), match.end(), match.group()))
        return matches
    
    @classmethod
    def detect_phones(cls, text: str) -> List[Tuple[int, int, str]]:
        """Detect phone numbers."""
        matches = []
        for pattern in cls.PHONE_PATTERNS:
            for match in pattern.finditer(text):
                # Avoid duplicates
                span = (match.start(), match.end())
                if not any(m[0] == span[0] and m[1] == span[1] for m in matches):
                    matches.append((match.start(), match.end(), match.group()))
        return matches
    
    @classmethod
    def detect_aadhaar(cls, text: str) -> List[Tuple[int, int, str]]:
        """Detect Aadhaar numbers."""
        matches = []
        for match in cls.AADHAAR_PATTERN.finditer(text):
            # Validate: should be 12 digits
            digits_only = re.sub(r'\D', '', match.group())
            if len(digits_only) == 12:
                matches.append((match.start(), match.end(), match.group()))
        return matches
    
    @classmethod
    def detect_pan(cls, text: str) -> List[Tuple[int, int, str]]:
        """Detect PAN numbers."""
        matches = []
        for match in cls.PAN_PATTERN.finditer(text):
            matches.append((match.start(), match.end(), match.group()))
        return matches
    
    @classmethod
    def detect_ip_addresses(cls, text: str) -> List[Tuple[int, int, str]]:
        """Detect IP addresses."""
        matches = []
        for match in cls.IP_PATTERN.finditer(text):
            ip = match.group()
            # Validate IP range
            parts = ip.split('.')
            if all(0 <= int(p) <= 255 for p in parts):
                matches.append((match.start(), match.end(), ip))
        return matches
    
    @classmethod
    def detect_credit_cards(cls, text: str) -> List[Tuple[int, int, str]]:
        """Detect credit card numbers."""
        matches = []
        for match in cls.CREDIT_CARD_PATTERN.finditer(text):
            digits_only = re.sub(r'\D', '', match.group())
            if len(digits_only) >= 13 and len(digits_only) <= 19:
                matches.append((match.start(), match.end(), match.group()))
        return matches
    
    @classmethod
    def detect_dob(cls, text: str) -> List[Tuple[int, int, str]]:
        """Detect dates of birth."""
        matches = []
        for pattern in cls.DOB_PATTERNS:
            for match in pattern.finditer(text):
                matches.append((match.start(), match.end(), match.group()))
        return matches
    
    @classmethod
    def detect_passport(cls, text: str) -> List[Tuple[int, int, str]]:
        """Detect passport numbers."""
        matches = []
        for match in cls.PASSPORT_PATTERN.finditer(text):
            matches.append((match.start(), match.end(), match.group()))
        return matches
    
    @classmethod
    def detect_bank_account(cls, text: str) -> List[Tuple[int, int, str]]:
        """Detect bank account numbers."""
        matches = []
        for match in cls.BANK_ACCOUNT_PATTERN.finditer(text):
            # Check if it could be an account number (not Aadhaar, not phone)
            digits = match.group()
            if len(digits) >= 9 and len(digits) <= 18:
                matches.append((match.start(), match.end(), digits))
        return matches
    
    @classmethod
    def detect_ifsc(cls, text: str) -> List[Tuple[int, int, str]]:
        """Detect IFSC codes."""
        matches = []
        for match in cls.IFSC_PATTERN.finditer(text):
            matches.append((match.start(), match.end(), match.group()))
        return matches
    
    @classmethod
    def detect_upi(cls, text: str) -> List[Tuple[int, int, str]]:
        """Detect UPI IDs."""
        matches = []
        for match in cls.UPI_PATTERN.finditer(text):
            upi = match.group()
            # Filter out emails - UPI should have @upi or @bankname
            if '@upi' in upi.lower() or any(bank in upi.lower() for bank in ['@ok', '@axis', '@hdfc', '@sbi', '@icici', '@pnb']):
                matches.append((match.start(), match.end(), upi))
        return matches
    
    @classmethod
    def detect_device_id(cls, text: str) -> List[Tuple[int, int, str]]:
        """Detect device IDs."""
        matches = []
        for match in cls.DEVICE_ID_PATTERN.finditer(text):
            matches.append((match.start(), match.end(), match.group()))
        return matches
    
    @classmethod
    def detect_fingerprint(cls, text: str) -> List[Tuple[int, int, str]]:
        """Detect fingerprint hashes."""
        matches = []
        for match in cls.FINGERPRINT_PATTERN.finditer(text):
            matches.append((match.start(), match.end(), match.group()))
        return matches
    
    @classmethod
    def detect_face_template(cls, text: str) -> List[Tuple[int, int, str]]:
        """Detect face template hashes."""
        matches = []
        for match in cls.FACE_TEMPLATE_PATTERN.finditer(text):
            matches.append((match.start(), match.end(), match.group()))
        return matches
    
    @classmethod
    def detect_addresses(cls, text: str) -> List[Tuple[int, int, str]]:
        """
        Detect addresses in text using multiple heuristics.
        Looks for address patterns with keywords and PIN codes.
        """
        matches = []
        
        # Pattern 1: Look for "address:" or "addr:" followed by text until punctuation or end
        address_prefix_pattern = re.compile(
            r'(?:address|addr)[:\s]+([^,.;]{10,100}?)(?=[,.;]|\n|$)',
            re.IGNORECASE
        )
        
        # Pattern 2: Look for street/road/building patterns with numbers
        street_pattern = re.compile(
            r'\b\d+\s+(?:[A-Za-z]+\s+)*(?:street|st|road|rd|avenue|ave|lane|ln|drive|dr|'
            r'boulevard|blvd|circle|cir|way|highway|hwy|parkway|pkwy)',
            re.IGNORECASE
        )
        
        # Pattern 3: Look for flat/apartment/house numbers
        unit_pattern = re.compile(
            r'(?:flat|apartment|apt|house|building|blk|block|unit|suite|room|floor|fl)'
            r'\s*[\dA-Z-]+[^,.;]{5,80}?(?=[,.;]|\n|$)',
            re.IGNORECASE
        )
        
        # Pattern 4: Look for city + PIN code patterns
        city_pin_pattern = re.compile(
            r'(?:mumbai|delhi|bangalore|chennai|kolkata|pune|hyderabad|ahmedabad|'
            r'jaipur|lucknow|kanpur|nagpur|indore|thane|bhopal|visakhapatnam|'
            r'pimpri|patna|vadodara|ghaziabad|ludhiana|agra|nashik|faridabad|'
            r'meerut|rajkot|kalyan|vasai|varanasi|srinagar|aurangabad|dhanbad|'
            r'amritsar|navi mumbai|allahabad|ranchi|howrah|coimbatore|jabalpur|'
            r'gwalior|vijayawada|jodhpur|madurai|raipur|kota|guwahati|chandigarh|'
            r'solapur|hubli|tiruchirappalli|bareilly|mysore|tiruppur|gurgaon|'
            r'aligarh|jalandhar|bhubaneswar|salem|warangal|guntur|bhiwandi|'
            r'saharanpur|gorakhpur|bikaner|amravati|noida|jamshedpur|bhilai|'
            r'cuttack|firozabad|kochi|nellore|bhavnagar|dehradun|durgapur|'
            r'asansol|rourkela|nanded|kolhapur|ajmer|akola|gulbarga|jamnagar|'
            r'ujjain|loni|siliguri|jhansi|ulhasnagar|jammu|sangli|mangalore|'
            r'erode|belgaum|ambattur|tirunelveli|malegaon|gaya|jalgaon|udaipur|'
            r'maheshtala)'
            r'[\s,]+\d{6}',
            re.IGNORECASE
        )
        
        # Find address prefix patterns
        for match in address_prefix_pattern.finditer(text):
            address_text = match.group(1).strip()
            if 10 <= len(address_text) <= 150:
                matches.append((match.start(1), match.end(1), address_text))
        
        # Find street patterns (with some context)
        for match in street_pattern.finditer(text):
            # Get context around the match
            start = max(0, match.start() - 20)
            end = min(len(text), match.end() + 50)
            address_text = text[start:end].strip()
            # Clean up - stop at common delimiters
            for delim in ['.', ';', '  ', '\n', 'phone', 'email', 'mobile']:
                if delim in address_text.lower():
                    idx = address_text.lower().find(delim)
                    if idx > 20:
                        address_text = address_text[:idx].strip()
            if 10 <= len(address_text) <= 150:
                # Check for duplicates
                span = (start, start + len(address_text))
                if not any(m[0] <= span[0] < m[1] or m[0] < span[1] <= m[1] for m in matches):
                    matches.append((span[0], span[1], address_text))
        
        # Find unit patterns
        for match in unit_pattern.finditer(text):
            address_text = match.group(0).strip()
            if 10 <= len(address_text) <= 150:
                span = (match.start(), match.end())
                if not any(m[0] <= span[0] < m[1] or m[0] < span[1] <= m[1] for m in matches):
                    matches.append((span[0], span[1], address_text))
        
        # Find city + PIN patterns
        for match in city_pin_pattern.finditer(text):
            address_text = match.group(0).strip()
            span = (match.start(), match.end())
            if not any(m[0] <= span[0] < m[1] or m[0] < span[1] <= m[1] for m in matches):
                matches.append((span[0], span[1], address_text))
        
        return matches


class NERDetector:
    """NLP/NER-based PII detector using spaCy."""
    
    def __init__(self):
        self.nlp = None
        self._load_model()
    
    def _load_model(self):
        """Load spaCy model."""
        if not SPACY_AVAILABLE:
            return
        
        try:
            self.nlp = spacy.load("en_core_web_sm")
        except OSError:
            # Model not installed, will use regex only
            self.nlp = None
    
    def detect(self, text: str) -> List[Tuple[int, int, str, str]]:
        """
        Detect PII using NER.
        Returns: List of (start, end, text, entity_type)
        """
        if self.nlp is None:
            return []
        
        matches = []
        doc = self.nlp(text)
        
        # Map spaCy entities to PII types
        entity_mapping = {
            'PERSON': 'PERSON_NAME',
            'GPE': 'LOCATION',
            'LOC': 'LOCATION',
            'ORG': 'ORGANIZATION',
        }
        
        for ent in doc.ents:
            if ent.label_ in entity_mapping:
                matches.append((
                    ent.start_char,
                    ent.end_char,
                    ent.text,
                    entity_mapping[ent.label_]
                ))
        
        return matches


class PIIDetectionEngine:
    """Main PII detection engine combining regex and NER."""
    
    def __init__(self):
        self.regex_detectors = RegexDetectors()
        self.ner_detector = NERDetector()
    
    def detect_all(self, text: str) -> List[PIIDetection]:
        """
        Detect all PII in text using hybrid approach.
        Returns merged and deduplicated detections.
        """
        all_detections = []
        
        # Regex-based detections
        regex_results = self._run_regex_detections(text)
        all_detections.extend(regex_results)
        
        # NER-based detections
        ner_results = self._run_ner_detections(text)
        all_detections.extend(ner_results)
        
        # Merge overlapping detections
        merged = self._merge_detections(all_detections)
        
        return merged
    
    def _run_regex_detections(self, text: str) -> List[PIIDetection]:
        """Run all regex detectors."""
        detections = []
        
        # Email
        for start, end, match_text in self.regex_detectors.detect_emails(text):
            detections.append(PIIDetection(
                entity_type='EMAIL',
                start=start,
                end=end,
                text=match_text,
                confidence=0.95,
                detection_method='regex'
            ))
        
        # Phone
        for start, end, match_text in self.regex_detectors.detect_phones(text):
            detections.append(PIIDetection(
                entity_type='PHONE',
                start=start,
                end=end,
                text=match_text,
                confidence=0.90,
                detection_method='regex'
            ))
        
        # Aadhaar
        for start, end, match_text in self.regex_detectors.detect_aadhaar(text):
            detections.append(PIIDetection(
                entity_type='AADHAAR',
                start=start,
                end=end,
                text=match_text,
                confidence=0.98,
                detection_method='regex'
            ))
        
        # PAN
        for start, end, match_text in self.regex_detectors.detect_pan(text):
            detections.append(PIIDetection(
                entity_type='PAN',
                start=start,
                end=end,
                text=match_text,
                confidence=0.98,
                detection_method='regex'
            ))
        
        # IP Address
        for start, end, match_text in self.regex_detectors.detect_ip_addresses(text):
            detections.append(PIIDetection(
                entity_type='IP_ADDRESS',
                start=start,
                end=end,
                text=match_text,
                confidence=0.95,
                detection_method='regex'
            ))
        
        # Credit Card
        for start, end, match_text in self.regex_detectors.detect_credit_cards(text):
            detections.append(PIIDetection(
                entity_type='CREDIT_CARD',
                start=start,
                end=end,
                text=match_text,
                confidence=0.85,
                detection_method='regex'
            ))
        
        # DOB
        for start, end, match_text in self.regex_detectors.detect_dob(text):
            detections.append(PIIDetection(
                entity_type='DOB',
                start=start,
                end=end,
                text=match_text,
                confidence=0.80,
                detection_method='regex'
            ))
        
        # Passport
        for start, end, match_text in self.regex_detectors.detect_passport(text):
            detections.append(PIIDetection(
                entity_type='PASSPORT',
                start=start,
                end=end,
                text=match_text,
                confidence=0.90,
                detection_method='regex'
            ))
        
        # Bank Account
        for start, end, match_text in self.regex_detectors.detect_bank_account(text):
            detections.append(PIIDetection(
                entity_type='BANK_ACCOUNT',
                start=start,
                end=end,
                text=match_text,
                confidence=0.85,
                detection_method='regex'
            ))
        
        # IFSC
        for start, end, match_text in self.regex_detectors.detect_ifsc(text):
            detections.append(PIIDetection(
                entity_type='IFSC',
                start=start,
                end=end,
                text=match_text,
                confidence=0.95,
                detection_method='regex'
            ))
        
        # UPI
        for start, end, match_text in self.regex_detectors.detect_upi(text):
            detections.append(PIIDetection(
                entity_type='UPI',
                start=start,
                end=end,
                text=match_text,
                confidence=0.90,
                detection_method='regex'
            ))
        
        # Device ID
        for start, end, match_text in self.regex_detectors.detect_device_id(text):
            detections.append(PIIDetection(
                entity_type='DEVICE_ID',
                start=start,
                end=end,
                text=match_text,
                confidence=0.95,
                detection_method='regex'
            ))
        
        # Fingerprint
        for start, end, match_text in self.regex_detectors.detect_fingerprint(text):
            detections.append(PIIDetection(
                entity_type='FINGERPRINT',
                start=start,
                end=end,
                text=match_text,
                confidence=0.98,
                detection_method='regex'
            ))
        
        # Face Template
        for start, end, match_text in self.regex_detectors.detect_face_template(text):
            detections.append(PIIDetection(
                entity_type='FACE_TEMPLATE',
                start=start,
                end=end,
                text=match_text,
                confidence=0.98,
                detection_method='regex'
            ))
        
        # Address
        for start, end, match_text in self.regex_detectors.detect_addresses(text):
            detections.append(PIIDetection(
                entity_type='ADDRESS',
                start=start,
                end=end,
                text=match_text,
                confidence=0.75,
                detection_method='regex'
            ))
        
        return detections
    
    def _run_ner_detections(self, text: str) -> List[PIIDetection]:
        """Run NER detector."""
        detections = []
        
        ner_results = self.ner_detector.detect(text)
        for start, end, match_text, entity_type in ner_results:
            detections.append(PIIDetection(
                entity_type=entity_type,
                start=start,
                end=end,
                text=match_text,
                confidence=0.85,
                detection_method='ner'
            ))
        
        return detections
    
    def _merge_detections(self, detections: List[PIIDetection]) -> List[PIIDetection]:
        """
        Merge overlapping detections.
        Priority: longer spans > higher confidence > regex > ner
        """
        if not detections:
            return []
        
        # Sort by start position
        sorted_detections = sorted(detections, key=lambda d: (d.start, -d.end))
        
        merged = []
        for detection in sorted_detections:
            # Check for overlap with existing merged detections
            overlap = False
            for i, existing in enumerate(merged):
                # Check if they overlap
                if not (detection.end <= existing.start or detection.start >= existing.end):
                    # Overlap detected - decide which to keep
                    existing_len = existing.end - existing.start
                    detection_len = detection.end - detection.start
                    
                    # Keep longer detection
                    if detection_len > existing_len:
                        merged[i] = detection
                    elif detection_len == existing_len:
                        # Same length - keep higher confidence or regex over ner
                        if detection.confidence > existing.confidence:
                            merged[i] = detection
                        elif detection.confidence == existing.confidence:
                            if detection.detection_method == 'regex' and existing.detection_method == 'ner':
                                merged[i] = detection
                    overlap = True
                    break
            
            if not overlap:
                merged.append(detection)
        
        # Sort by position
        merged.sort(key=lambda d: d.start)
        
        return merged
    
    def get_entity_counts(self, detections: List[PIIDetection]) -> Dict[str, int]:
        """Get count of each entity type."""
        counts = defaultdict(int)
        for detection in detections:
            counts[detection.entity_type] += 1
        return dict(counts)
    
    def detections_to_json(self, detections: List[PIIDetection]) -> str:
        """Convert detections to JSON string."""
        return json.dumps([d.to_dict() for d in detections])


# Global instance
detection_engine = PIIDetectionEngine()


def detect_pii(text: str) -> Tuple[List[PIIDetection], Dict[str, int]]:
    """
    Convenience function to detect PII in text.
    Returns: (detections, entity_counts)
    """
    detections = detection_engine.detect_all(text)
    counts = detection_engine.get_entity_counts(detections)
    return detections, counts
