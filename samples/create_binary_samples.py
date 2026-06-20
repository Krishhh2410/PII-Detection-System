#!/usr/bin/env python3
"""
Create sample PDF and DOCX files with PII for testing.
This script creates minimal valid files with embedded PII.
"""
import os

# Sample PDF content with PII (minimal valid PDF structure)
# This creates a text-based PDF with embedded PII
PDF_CONTENT = b"""%PDF-1.4
1 0 obj
<<
/Type /Catalog
/Pages 2 0 R
>>
endobj
2 0 obj
<<
/Type /Pages
/Kids [3 0 R]
/Count 1
>>
endobj
3 0 obj
<<
/Type /Page
/Parent 2 0 R
/MediaBox [0 0 612 792]
/Contents 4 0 R
/Resources <<
/Font <<
/F1 5 0 R
>>
>>
>>
endobj
4 0 obj
<<
/Length 800
>>
stream
BT
/F1 18 Tf
100 750 Td
(Employee Information Report) Tj
0 -30 Td
/F1 12 Tf
(Confidential - Internal Use Only) Tj
0 -30 Td
(Company: TechCorp India Pvt Ltd) Tj
0 -20 Td
(Document ID: DOC-2024-001) Tj
0 -40 Td
/F1 14 Tf
(Employee Details:) Tj
0 -25 Td
/F1 10 Tf
(Name: Rajesh Kumar) Tj
0 -15 Td
(Email: rajesh.kumar@techcorp.in) Tj
0 -15 Td
(Phone: +91-9876543210) Tj
0 -15 Td
(Aadhaar: 1234 5678 9012) Tj
0 -15 Td
(PAN: ABCDE1234F) Tj
0 -15 Td
(Address: 123 MG Road, Bangalore, Karnataka 560001) Tj
0 -15 Td
(IP Address: 192.168.1.100) Tj
0 -30 Td
(Name: Priya Sharma) Tj
0 -15 Td
(Email: priya.sharma@techcorp.in) Tj
0 -15 Td
(Phone: 09876543210) Tj
0 -15 Td
(Aadhaar: 9876 5432 1098) Tj
0 -15 Td
(PAN: FGHIJ5678K) Tj
0 -15 Td
(Address: 456 Park Street, Mumbai, Maharashtra 400001) Tj
0 -15 Td
(IP Address: 10.0.0.50) Tj
0 -30 Td
(Name: Amit Patel) Tj
0 -15 Td
(Email: amit.patel@gmail.com) Tj
0 -15 Td
(Phone: +91 87654 32109) Tj
0 -15 Td
(Aadhaar: 4567 8901 2345) Tj
0 -15 Td
(PAN: KLMNO9012P) Tj
0 -15 Td
(Address: 789 Nehru Place, New Delhi, Delhi 110019) Tj
0 -15 Td
(IP Address: 172.16.0.25) Tj
ET
endstream
endobj
5 0 obj
<<
/Type /Font
/Subtype /Type1
/BaseFont /Helvetica
>>
endobj
xref
0 6
0000000000 65535 f 
0000000009 00000 n 
0000000058 00000 n 
0000000115 00000 n 
0000000266 00000 n 
0000001119 00000 n 
trailer
<<
/Size 6
/Root 1 0 R
>>
startxref
1205
%%EOF
"""

# Sample DOCX content (ZIP archive with XML files)
# This is a minimal DOCX structure with PII
DOCX_CONTENT = None  # We'll create this using zipfile


def create_sample_pdf(output_path: str):
    """Create a sample PDF file with PII."""
    with open(output_path, 'wb') as f:
        f.write(PDF_CONTENT)
    print(f"Created: {output_path}")


def create_sample_docx(output_path: str):
    """Create a sample DOCX file with PII using zipfile."""
    import zipfile
    import io
    
    # Create a minimal DOCX structure
    docx_buffer = io.BytesIO()
    
    with zipfile.ZipFile(docx_buffer, 'w', zipfile.ZIP_DEFLATED) as zf:
        # [Content_Types].xml
        content_types = b'''<?xml version="1.0" encoding="UTF-8" standalone="yes"?>
<Types xmlns="http://schemas.openxmlformats.org/package/2006/content-types">
<Default Extension="rels" ContentType="application/vnd.openxmlformats-package.relationships+xml"/>
<Default Extension="xml" ContentType="application/xml"/>
<Override PartName="/word/document.xml" ContentType="application/vnd.openxmlformats-officedocument.wordprocessingml.document.main+xml"/>
</Types>'''
        zf.writestr('[Content_Types].xml', content_types)
        
        # _rels/.rels
        rels = b'''<?xml version="1.0" encoding="UTF-8" standalone="yes"?>
<Relationships xmlns="http://schemas.openxmlformats.org/package/2006/relationships">
<Relationship Id="rId1" Type="http://schemas.openxmlformats.org/officeDocument/2006/relationships/officeDocument" Target="word/document.xml"/>
</Relationships>'''
        zf.writestr('_rels/.rels', rels)
        
        # word/_rels/document.xml.rels
        doc_rels = b'''<?xml version="1.0" encoding="UTF-8" standalone="yes"?>
<Relationships xmlns="http://schemas.openxmlformats.org/package/2006/relationships">
</Relationships>'''
        zf.writestr('word/_rels/document.xml.rels', doc_rels)
        
        # word/document.xml with PII content
        document_xml = b'''<?xml version="1.0" encoding="UTF-8" standalone="yes"?>
<w:document xmlns:w="http://schemas.openxmlformats.org/wordprocessingml/2006/main">
<w:body>
<w:p><w:pPr><w:pStyle w:val="Title"/></w:pPr><w:r><w:t>Customer Data Export</w:t></w:r></w:p>
<w:p><w:r><w:t>Confidential Document - TechCorp India Pvt Ltd</w:t></w:r></w:p>
<w:p><w:r><w:t>Generated: January 15, 2024</w:t></w:r></w:p>
<w:p><w:r><w:t xml:space="preserve"> </w:t></w:r></w:p>
<w:p><w:pPr><w:pStyle w:val="Heading1"/></w:pPr><w:r><w:t>Customer Contact Information</w:t></w:r></w:p>
<w:p><w:r><w:t xml:space="preserve"> </w:t></w:r></w:p>
<w:p><w:r><w:t>Name: Rahul Verma</w:t></w:r></w:p>
<w:p><w:r><w:t>Email: rahul.verma@email.com</w:t></w:r></w:p>
<w:p><w:r><w:t>Phone: 919988776655</w:t></w:r></w:p>
<w:p><w:r><w:t>Alternate Phone: +91-11-12345678</w:t></w:r></w:p>
<w:p><w:r><w:t>Aadhaar: 5678 9012 3456</w:t></w:r></w:p>
<w:p><w:r><w:t>PAN: XYZAB5678C</w:t></w:r></w:p>
<w:p><w:r><w:t>Address: 12 Jubilee Hills, Hyderabad 500033</w:t></w:r></w:p>
<w:p><w:r><w:t>Office: Madhapur, Hyderabad 500081</w:t></w:r></w:p>
<w:p><w:r><w:t>Date of Birth: 03 December 1987</w:t></w:r></w:p>
<w:p><w:r><w:t>IP Address: 198.51.100.25</w:t></w:r></w:p>
<w:p><w:r><w:t>Credit Card: 4111-1111-1111-1111</w:t></w:r></w:p>
<w:p><w:r><w:t xml:space="preserve"> </w:t></w:r></w:p>
<w:p><w:r><w:t>Name: Ananya Gupta</w:t></w:r></w:p>
<w:p><w:r><w:t>Email: ananya.gupta@customer.in</w:t></w:r></w:p>
<w:p><w:r><w:t>Phone: +91-9988776655</w:t></w:r></w:p>
<w:p><w:r><w:t>Alternate Phone: 022-12345678</w:t></w:r></w:p>
<w:p><w:r><w:t>Aadhaar: 3456 7890 1234</w:t></w:r></w:p>
<w:p><w:r><w:t>PAN: ABCPQ1234D</w:t></w:r></w:p>
<w:p><w:r><w:t>Address: 45 Salt Lake, Kolkata, West Bengal 700091</w:t></w:r></w:p>
<w:p><w:r><w:t>Office: Sector 5, Kolkata 700091</w:t></w:r></w:p>
<w:p><w:r><w:t>Date of Birth: 20 May 1995</w:t></w:r></w:p>
<w:p><w:r><w:t>IP Address: 203.0.113.50</w:t></w:r></w:p>
<w:p><w:r><w:t>Credit Card: 4532-1234-5678-9012</w:t></w:r></w:p>
<w:p><w:r><w:t xml:space="preserve"> </w:t></w:r></w:p>
<w:p><w:r><w:t>Name: Rajesh Kumar</w:t></w:r></w:p>
<w:p><w:r><w:t>Email: rajesh.kumar@techcorp.in</w:t></w:r></w:p>
<w:p><w:r><w:t>Phone: +91-9876543210</w:t></w:r></w:p>
<w:p><w:r><w:t>Aadhaar: 1234 5678 9012</w:t></w:r></w:p>
<w:p><w:r><w:t>PAN: ABCDE1234F</w:t></w:r></w:p>
<w:p><w:r><w:t>Address: 123 MG Road, Bangalore, Karnataka 560001</w:t></w:r></w:p>
<w:p><w:r><w:t>IP Address: 192.168.1.100</w:t></w:r></w:p>
<w:p><w:r><w:t>Credit Card: 3712-345678-90123</w:t></w:r></w:p>
<w:p><w:r><w:t xml:space="preserve"> </w:t></w:r></w:p>
<w:p><w:pPr><w:pStyle w:val="Heading1"/></w:pPr><w:r><w:t>System Access Logs</w:t></w:r></w:p>
<w:p><w:r><w:t>admin@techcorp.in accessed from 192.168.1.1 at 2024-01-15 10:30:00</w:t></w:r></w:p>
<w:p><w:r><w:t>manager@techcorp.in accessed from 10.0.0.100 at 2024-01-15 14:45:00</w:t></w:r></w:p>
<w:p><w:r><w:t>rajesh.kumar@techcorp.in accessed from 172.16.0.50 at 2024-01-15 16:20:00</w:t></w:r></w:p>
<w:sectPr><w:pgSz w:w="12240" w:h="15840"/><w:pgMar w:top="1440" w:right="1440" w:bottom="1440" w:left="1440"/></w:sectPr>
</w:body>
</w:document>'''
        zf.writestr('word/document.xml', document_xml)
    
    # Write to file
    with open(output_path, 'wb') as f:
        f.write(docx_buffer.getvalue())
    
    print(f"Created: {output_path}")


if __name__ == "__main__":
    script_dir = os.path.dirname(os.path.abspath(__file__))
    
    pdf_path = os.path.join(script_dir, "sample_document.pdf")
    docx_path = os.path.join(script_dir, "sample_document.docx")
    
    create_sample_pdf(pdf_path)
    create_sample_docx(docx_path)
    
    print("\nSample files generated successfully!")
    print(f"- SQL file: {os.path.join(script_dir, 'sample_data.sql')}")
    print(f"- PDF file: {pdf_path}")
    print(f"- DOCX file: {docx_path}")
