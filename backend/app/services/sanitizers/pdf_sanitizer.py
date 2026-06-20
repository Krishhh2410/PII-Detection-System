import io
from typing import List
import fitz  # PyMuPDF

from app.services.sanitizers.base import BaseSanitizer
from app.services.pii_detector import PIIDetection


class PDFSanitizer(BaseSanitizer):
    """Sanitizer for PDF files."""
    
    def sanitize(self, content: bytes, detections: List[PIIDetection]) -> bytes:
        """
        Sanitize PDF content by redacting detected PII.
        Uses PyMuPDF to create a redacted copy.
        """
        # Open PDF from bytes
        doc = fitz.open(stream=content, filetype="pdf")
        
        # Sort detections by page if available, otherwise treat as single page
        # For now, we search text in the entire document
        
        # Process each page
        for page_num in range(len(doc)):
            page = doc[page_num]
            
            # Get text and search for PII to redact
            text = page.get_text()
            
            # For each detection, find its occurrences on this page
            for detection in detections:
                search_text = detection.text
                sanitized_text = self.apply_anonymization(search_text, detection)
                
                # Find all occurrences of this text on the page
                text_instances = page.search_for(search_text)
                
                # Add redaction annotations
                for inst in text_instances:
                    # Add redaction annotation
                    page.add_redact_annot(inst, text=sanitized_text)
                
                # Also search for partial matches if exact match fails
                if not text_instances:
                    # Try to find similar text
                    words = search_text.split()
                    if words:
                        partial_instances = page.search_for(words[0])
                        for inst in partial_instances:
                            page.add_redact_annot(inst, text=sanitized_text)
            
            # Apply redactions on this page
            page.apply_redactions()
        
        # Save to bytes
        output = io.BytesIO()
        doc.save(output)
        doc.close()
        
        return output.getvalue()
    
    def extract_text(self, content: bytes) -> str:
        """Extract text from PDF for PII detection."""
        doc = fitz.open(stream=content, filetype="pdf")
        text = ""
        for page in doc:
            text += page.get_text()
        doc.close()
        return text
