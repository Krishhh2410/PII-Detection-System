"""Analysis and preview endpoints for PII detection."""
import json
from typing import List, Optional, Dict, Any
from fastapi import APIRouter, Depends, HTTPException, Request
from pydantic import BaseModel
from sqlalchemy.orm import Session

from app.database import get_db
from app.models.user import User
from app.routers.auth import get_current_active_user, get_current_admin
from app.services.pii_detector import detect_pii, detection_engine, PIIDetection
from app.services.sanitizers.text_sanitizer import TextSanitizer
from app.services.audit_service import AuditService

router = APIRouter(prefix="/analysis", tags=["analysis"])


# ==================== Pydantic Models ====================

class TextAnalysisRequest(BaseModel):
    text: str
    mode: str = "mask"  # mask, redact, tokenize


class PIIDetectionResponse(BaseModel):
    entity_type: str
    start: int
    end: int
    text: str
    confidence: float
    detection_method: str


class TextAnalysisResponse(BaseModel):
    original_text: str
    sanitized_text: str
    detections: List[PIIDetectionResponse]
    entity_counts: Dict[str, int]
    total_entities: int


class BatchAnalysisRequest(BaseModel):
    texts: List[str]
    mode: str = "mask"


class BatchAnalysisResponse(BaseModel):
    results: List[TextAnalysisResponse]
    summary: Dict[str, Any]


class ComparisonRequest(BaseModel):
    text: str


class ComparisonResponse(BaseModel):
    original_text: str
    mask_version: str
    redact_version: str
    tokenize_version: str
    detections: List[PIIDetectionResponse]
    entity_counts: Dict[str, int]


class HighlightedTextResponse(BaseModel):
    html: str
    detections: List[PIIDetectionResponse]
    entity_counts: Dict[str, int]


# ==================== Helper Functions ====================

PII_COLORS = {
    "EMAIL": "#FF6B6B",
    "PHONE": "#4ECDC4",
    "AADHAAR": "#45B7D1",
    "PAN": "#96CEB4",
    "IP_ADDRESS": "#FFEAA7",
    "CREDIT_CARD": "#DDA0DD",
    "PERSON_NAME": "#98D8C8",
    "LOCATION": "#F7DC6F",
    "ORGANIZATION": "#BB8FCE",
    "DOB": "#85C1E9",
    "PASSPORT": "#F8C471",
    "BANK_ACCOUNT": "#82E0AA",
    "IFSC": "#F1948A",
    "UPI": "#85C1E9",
    "DEVICE_ID": "#D7BDE2",
    "FINGERPRINT": "#A9DFBF",
    "FACE_TEMPLATE": "#AED6F1",
    "ADDRESS": "#F9E79F",
}


def get_pii_color(entity_type: str) -> str:
    """Get color for PII entity type."""
    return PII_COLORS.get(entity_type, "#BDC3C7")


def create_highlighted_html(text: str, detections: List[PIIDetection]) -> str:
    """Create HTML with highlighted PII entities."""
    # Sort by position in reverse order to avoid offset issues
    sorted_detections = sorted(detections, key=lambda d: d.start, reverse=True)
    
    html_parts = []
    last_end = len(text)
    
    for detection in sorted_detections:
        # Add text after this detection
        html_parts.append(text[detection.end:last_end])
        
        # Add highlighted detection
        color = get_pii_color(detection.entity_type)
        highlighted = (
            f'<span style="background-color: {color}; padding: 2px 4px; '
            f'border-radius: 3px; font-weight: 500;" '
            f'title="{detection.entity_type} (confidence: {detection.confidence:.2f})">'
            f'{text[detection.start:detection.end]}</span>'
        )
        html_parts.append(highlighted)
        last_end = detection.start
    
    # Add remaining text
    html_parts.append(text[:last_end])
    
    # Reverse and join
    return "".join(reversed(html_parts))


def apply_sanitization(text: str, detections: List[PIIDetection], mode: str) -> str:
    """Apply sanitization to text."""
    sanitizer = TextSanitizer(mode=mode)
    
    # Sort by position in reverse order
    sorted_detections = sorted(detections, key=lambda d: d.start, reverse=True)
    
    result = text
    for detection in sorted_detections:
        original_text = result[detection.start:detection.end]
        sanitized_text = sanitizer.apply_anonymization(original_text, detection)
        result = result[:detection.start] + sanitized_text + result[detection.end:]
    
    return result


# ==================== Endpoints ====================

@router.post("/text", response_model=TextAnalysisResponse)
async def analyze_text(
    request: TextAnalysisRequest,
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_active_user)
):
    """
    Analyze text for PII and return sanitized version.
    """
    # Validate mode
    if request.mode not in ["mask", "redact", "tokenize"]:
        raise HTTPException(status_code=400, detail="Invalid mode. Use: mask, redact, tokenize")
    
    # Detect PII
    detections, entity_counts = detect_pii(request.text)
    
    # Sanitize text
    sanitized_text = apply_sanitization(request.text, detections, request.mode)
    
    # Convert detections to response format
    detection_responses = [
        PIIDetectionResponse(
            entity_type=d.entity_type,
            start=d.start,
            end=d.end,
            text=d.text,
            confidence=d.confidence,
            detection_method=d.detection_method
        )
        for d in detections
    ]
    
    return TextAnalysisResponse(
        original_text=request.text,
        sanitized_text=sanitized_text,
        detections=detection_responses,
        entity_counts=entity_counts,
        total_entities=sum(entity_counts.values())
    )


@router.post("/highlight", response_model=HighlightedTextResponse)
async def highlight_pii(
    request: TextAnalysisRequest,
    current_user: User = Depends(get_current_active_user)
):
    """
    Analyze text and return HTML with highlighted PII entities.
    """
    # Detect PII
    detections, entity_counts = detect_pii(request.text)
    
    # Create highlighted HTML
    html = create_highlighted_html(request.text, detections)
    
    # Wrap in a styled container
    styled_html = f"""
    <div style="font-family: 'Segoe UI', Tahoma, Geneva, Verdana, sans-serif; 
                line-height: 1.6; padding: 15px; background-color: #f8f9fa; 
                border-radius: 8px; border: 1px solid #dee2e6;">
        {html}
    </div>
    """
    
    detection_responses = [
        PIIDetectionResponse(
            entity_type=d.entity_type,
            start=d.start,
            end=d.end,
            text=d.text,
            confidence=d.confidence,
            detection_method=d.detection_method
        )
        for d in detections
    ]
    
    return HighlightedTextResponse(
        html=styled_html,
        detections=detection_responses,
        entity_counts=entity_counts
    )


@router.post("/compare", response_model=ComparisonResponse)
async def compare_modes(
    request: ComparisonRequest,
    current_user: User = Depends(get_current_active_user)
):
    """
    Compare all three sanitization modes on the same text.
    """
    # Detect PII
    detections, entity_counts = detect_pii(request.text)
    
    # Apply all three modes
    mask_version = apply_sanitization(request.text, detections, "mask")
    redact_version = apply_sanitization(request.text, detections, "redact")
    tokenize_version = apply_sanitization(request.text, detections, "tokenize")
    
    detection_responses = [
        PIIDetectionResponse(
            entity_type=d.entity_type,
            start=d.start,
            end=d.end,
            text=d.text,
            confidence=d.confidence,
            detection_method=d.detection_method
        )
        for d in detections
    ]
    
    return ComparisonResponse(
        original_text=request.text,
        mask_version=mask_version,
        redact_version=redact_version,
        tokenize_version=tokenize_version,
        detections=detection_responses,
        entity_counts=entity_counts
    )


@router.post("/batch", response_model=BatchAnalysisResponse)
async def batch_analyze(
    request: BatchAnalysisRequest,
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_active_user)
):
    """
    Analyze multiple texts in a single request.
    """
    if request.mode not in ["mask", "redact", "tokenize"]:
        raise HTTPException(status_code=400, detail="Invalid mode. Use: mask, redact, tokenize")
    
    results = []
    total_entities = 0
    all_entity_counts: Dict[str, int] = {}
    
    for text in request.texts:
        detections, entity_counts = detect_pii(text)
        sanitized_text = apply_sanitization(text, detections, request.mode)
        
        detection_responses = [
            PIIDetectionResponse(
                entity_type=d.entity_type,
                start=d.start,
                end=d.end,
                text=d.text,
                confidence=d.confidence,
                detection_method=d.detection_method
            )
            for d in detections
        ]
        
        results.append(TextAnalysisResponse(
            original_text=text,
            sanitized_text=sanitized_text,
            detections=detection_responses,
            entity_counts=entity_counts,
            total_entities=sum(entity_counts.values())
        ))
        
        total_entities += sum(entity_counts.values())
        for entity, count in entity_counts.items():
            all_entity_counts[entity] = all_entity_counts.get(entity, 0) + count
    
    summary = {
        "total_texts": len(request.texts),
        "total_entities_detected": total_entities,
        "entity_type_breakdown": all_entity_counts,
        "average_entities_per_text": total_entities / len(request.texts) if request.texts else 0
    }
    
    return BatchAnalysisResponse(results=results, summary=summary)


@router.get("/entity-types")
async def get_entity_types(
    current_user: User = Depends(get_current_active_user)
):
    """
    Get all supported PII entity types with their colors.
    """
    return {
        "entity_types": [
            {"type": entity_type, "color": color, "description": get_entity_description(entity_type)}
            for entity_type, color in PII_COLORS.items()
        ]
    }


def get_entity_description(entity_type: str) -> str:
    """Get description for entity type."""
    descriptions = {
        "EMAIL": "Email addresses",
        "PHONE": "Phone numbers",
        "AADHAAR": "Indian Aadhaar numbers",
        "PAN": "Indian PAN card numbers",
        "IP_ADDRESS": "IP addresses",
        "CREDIT_CARD": "Credit card numbers",
        "PERSON_NAME": "Person names",
        "LOCATION": "Geographic locations",
        "ORGANIZATION": "Organization names",
        "DOB": "Dates of birth",
        "PASSPORT": "Passport numbers",
        "BANK_ACCOUNT": "Bank account numbers",
        "IFSC": "Indian IFSC codes",
        "UPI": "UPI IDs",
        "DEVICE_ID": "Device identifiers",
        "FINGERPRINT": "Fingerprint hashes",
        "FACE_TEMPLATE": "Face template hashes",
        "ADDRESS": "Physical addresses",
    }
    return descriptions.get(entity_type, "Unknown entity type")
