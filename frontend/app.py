import streamlit as st
import requests
import json
from datetime import datetime
import pandas as pd
import plotly.express as px
import plotly.graph_objects as go
from plotly.subplots import make_subplots

# Configure page with modern theme
st.set_page_config(
    page_title="PII Shield - Detection & Sanitization",
    page_icon="🛡️",
    layout="wide",
    initial_sidebar_state="expanded"
)

# Custom CSS for modern, beautiful UI
st.markdown("""
<style>
    /* Modern color palette */
    :root {
        --primary: #6366f1;
        --primary-dark: #4f46e5;
        --secondary: #ec4899;
        --success: #10b981;
        --warning: #f59e0b;
        --danger: #ef4444;
        --bg-dark: #0f172a;
        --bg-card: #1e293b;
        --text-primary: #f8fafc;
        --text-secondary: #94a3b8;
    }
    
    /* Global styles */
    .stApp {
        background: linear-gradient(135deg, #0f172a 0%, #1e293b 100%);
    }
    
    /* Sidebar styling */
    .css-1d391kg {
        background: linear-gradient(180deg, #1e293b 0%, #0f172a 100%);
    }
    
    /* Card styling */
    .pii-card {
        background: linear-gradient(135deg, #1e293b 0%, #334155 100%);
        border-radius: 16px;
        padding: 24px;
        margin: 12px 0;
        border: 1px solid rgba(99, 102, 241, 0.2);
        box-shadow: 0 4px 20px rgba(0, 0, 0, 0.3);
        transition: transform 0.3s ease, box-shadow 0.3s ease;
    }
    
    .pii-card:hover {
        transform: translateY(-2px);
        box-shadow: 0 8px 30px rgba(99, 102, 241, 0.2);
    }
    
    /* Metric cards */
    .metric-container {
        background: linear-gradient(135deg, #6366f1 0%, #8b5cf6 100%);
        border-radius: 12px;
        padding: 20px;
        text-align: center;
        color: white;
        box-shadow: 0 4px 15px rgba(99, 102, 241, 0.4);
    }
    
    .metric-value {
        font-size: 2.5rem;
        font-weight: 700;
        margin: 0;
    }
    
    .metric-label {
        font-size: 0.9rem;
        opacity: 0.9;
        margin-top: 4px;
    }
    
    /* Entity badges */
    .entity-badge {
        display: inline-block;
        padding: 4px 12px;
        border-radius: 20px;
        font-size: 0.75rem;
        font-weight: 600;
        margin: 2px;
        color: white;
    }
    
    /* Buttons */
    .stButton > button {
        background: linear-gradient(135deg, #6366f1 0%, #8b5cf6 100%);
        color: white;
        border: none;
        border-radius: 8px;
        padding: 12px 24px;
        font-weight: 600;
        transition: all 0.3s ease;
    }
    
    .stButton > button:hover {
        transform: translateY(-2px);
        box-shadow: 0 4px 15px rgba(99, 102, 241, 0.4);
    }
    
    /* Tabs */
    .stTabs [data-baseweb="tab-list"] {
        gap: 8px;
        background: rgba(30, 41, 59, 0.5);
        padding: 8px;
        border-radius: 12px;
    }
    
    .stTabs [data-baseweb="tab"] {
        background: transparent;
        border-radius: 8px;
        color: #94a3b8;
        font-weight: 500;
    }
    
    .stTabs [aria-selected="true"] {
        background: linear-gradient(135deg, #6366f1 0%, #8b5cf6 100%) !important;
        color: white !important;
    }
    
    /* Text areas */
    .stTextArea > div > div {
        background: #1e293b;
        border: 1px solid rgba(99, 102, 241, 0.3);
        border-radius: 12px;
        color: #f8fafc;
    }
    
    /* Expander */
    .streamlit-expanderHeader {
        background: linear-gradient(135deg, #1e293b 0%, #334155 100%);
        border-radius: 12px;
        border: 1px solid rgba(99, 102, 241, 0.2);
    }
    
    /* Success/Error messages */
    .stSuccess {
        background: rgba(16, 185, 129, 0.1);
        border: 1px solid rgba(16, 185, 129, 0.3);
        border-radius: 12px;
    }
    
    .stError {
        background: rgba(239, 68, 68, 0.1);
        border: 1px solid rgba(239, 68, 68, 0.3);
        border-radius: 12px;
    }
    
    /* Custom scrollbar */
    ::-webkit-scrollbar {
        width: 8px;
        height: 8px;
    }
    
    ::-webkit-scrollbar-track {
        background: #0f172a;
    }
    
    ::-webkit-scrollbar-thumb {
        background: #6366f1;
        border-radius: 4px;
    }
    
    ::-webkit-scrollbar-thumb:hover {
        background: #8b5cf6;
    }
    
    /* Animation for loading */
    @keyframes pulse {
        0%, 100% { opacity: 1; }
        50% { opacity: 0.5; }
    }
    
    .loading {
        animation: pulse 2s cubic-bezier(0.4, 0, 0.6, 1) infinite;
    }
</style>
""", unsafe_allow_html=True)

# API base URL
API_URL = "http://localhost:8004"

# Initialize session state
if "token" not in st.session_state:
    st.session_state.token = None
if "user" not in st.session_state:
    st.session_state.user = None
if "entity_colors" not in st.session_state:
    st.session_state.entity_colors = {}


def login(username, password):
    """Login and get token."""
    response = requests.post(
        f"{API_URL}/auth/login",
        data={"username": username, "password": password}
    )
    if response.status_code == 200:
        data = response.json()
        st.session_state.token = data["access_token"]
        st.session_state.user = data["user"]
        return True
    return False


def logout():
    """Logout and clear session."""
    st.session_state.token = None
    st.session_state.user = None
    st.rerun()


def get_headers():
    """Get headers with authorization."""
    if st.session_state.token:
        return {"Authorization": f"Bearer {st.session_state.token}"}
    return {}


def fetch_entity_colors():
    """Fetch entity type colors from API."""
    response = requests.get(f"{API_URL}/analysis/entity-types", headers=get_headers())
    if response.status_code == 200:
        data = response.json()
        for et in data.get("entity_types", []):
            st.session_state.entity_colors[et["type"]] = et["color"]


def get_entity_color(entity_type):
    """Get color for entity type."""
    return st.session_state.entity_colors.get(entity_type, "#6366f1")


# ==================== Sidebar ====================

with st.sidebar:
    st.markdown("""
    <div style="text-align: center; padding: 20px 0;">
        <h1 style="color: #6366f1; font-size: 2rem; margin: 0;">🛡️ PII Shield</h1>
        <p style="color: #94a3b8; margin-top: 8px;">Advanced PII Detection & Sanitization</p>
    </div>
    """, unsafe_allow_html=True)
    
    if st.session_state.user:
        st.markdown(f"""
        <div class="pii-card" style="text-align: center;">
            <h3 style="margin: 0; color: #f8fafc;">Welcome, {st.session_state.user['username']}!</h3>
            <span style="background: {'linear-gradient(135deg, #f59e0b 0%, #d97706 100%)' if st.session_state.user['role'] == 'admin' else 'linear-gradient(135deg, #6366f1 0%, #8b5cf6 100%)'}; 
                        color: white; padding: 4px 12px; border-radius: 20px; font-size: 0.8rem;">
                {'👑 Admin' if st.session_state.user['role'] == 'admin' else '👤 Standard User'}
            </span>
        </div>
        """, unsafe_allow_html=True)
        
        st.divider()
        
        # Navigation with icons
        nav_options = ["📊 Dashboard", "🔍 Text Analyzer", "📁 Files"]
        if st.session_state.user['role'] == 'admin':
            nav_options.extend(["⬆️ Upload", "📈 Analytics", "👥 Users", "📋 Audit Logs"])
        
        page = st.radio("Navigation", nav_options, label_visibility="collapsed")
        
        st.divider()
        
        if st.button("🚪 Logout", use_container_width=True):
            logout()
    else:
        st.info("Please login to continue")
        page = "Login"


# ==================== Login Page ====================

if not st.session_state.user:
    st.markdown("""
    <div style="text-align: center; padding: 60px 20px;">
        <h1 style="font-size: 3rem; background: linear-gradient(135deg, #6366f1 0%, #ec4899 100%); 
                   -webkit-background-clip: text; -webkit-text-fill-color: transparent;">
            🔐 Secure Login
        </h1>
        <p style="color: #94a3b8; font-size: 1.2rem;">Protecting sensitive data with AI-powered detection</p>
    </div>
    """, unsafe_allow_html=True)
    
    col1, col2, col3 = st.columns([1, 2, 1])
    
    with col2:
        with st.form("login_form"):
            st.markdown("<h3 style='color: #f8fafc; text-align: center;'>Enter Credentials</h3>", unsafe_allow_html=True)
            username = st.text_input("Username", placeholder="Enter your username")
            password = st.text_input("Password", type="password", placeholder="Enter your password")
            submit = st.form_submit_button("🔓 Login", use_container_width=True)
            
            if submit:
                if login(username, password):
                    st.success("✅ Login successful!")
                    st.rerun()
                else:
                    st.error("❌ Invalid username or password")
        
        st.markdown("""
        <div style="background: rgba(99, 102, 241, 0.1); border: 1px solid rgba(99, 102, 241, 0.3); 
                    border-radius: 12px; padding: 16px; margin-top: 20px;">
            <p style="color: #94a3b8; margin: 0; text-align: center;">
                <strong>Default Admin:</strong> username=<code>admin</code>, password=<code>admin123</code>
            </p>
        </div>
        """, unsafe_allow_html=True)


# ==================== Dashboard Page ====================

elif page == "📊 Dashboard":
    st.markdown("""
    <div style="margin-bottom: 30px;">
        <h1 style="color: #f8fafc; margin: 0;">📊 Dashboard</h1>
        <p style="color: #94a3b8;">Overview of PII detection and system activity</p>
    </div>
    """, unsafe_allow_html=True)
    
    # Fetch stats for admin, or simple message for standard user
    if st.session_state.user['role'] == 'admin':
        response = requests.get(f"{API_URL}/admin/stats", headers=get_headers())
        if response.status_code == 200:
            stats = response.json()
            
            # Key metrics row
            col1, col2, col3, col4 = st.columns(4)
            
            with col1:
                st.markdown(f"""
                <div class="metric-container">
                    <p class="metric-value">{stats['users']['total']}</p>
                    <p class="metric-label">Total Users</p>
                </div>
                """, unsafe_allow_html=True)
            
            with col2:
                st.markdown(f"""
                <div class="metric-container" style="background: linear-gradient(135deg, #ec4899 0%, #f43f5e 100%);">
                    <p class="metric-value">{stats['files']['total']}</p>
                    <p class="metric-label">Files Processed</p>
                </div>
                """, unsafe_allow_html=True)
            
            with col3:
                st.markdown(f"""
                <div class="metric-container" style="background: linear-gradient(135deg, #10b981 0%, #059669 100%);">
                    <p class="metric-value">{stats['pii_stats']['total_entities_detected']}</p>
                    <p class="metric-label">PII Entities Detected</p>
                </div>
                """, unsafe_allow_html=True)
            
            with col4:
                completion_rate = (stats['files']['completed'] / stats['files']['total'] * 100) if stats['files']['total'] > 0 else 0
                st.markdown(f"""
                <div class="metric-container" style="background: linear-gradient(135deg, #f59e0b 0%, #d97706 100%);">
                    <p class="metric-value">{completion_rate:.0f}%</p>
                    <p class="metric-label">Completion Rate</p>
                </div>
                """, unsafe_allow_html=True)
            
            st.markdown("<br>", unsafe_allow_html=True)
            
            # Charts row
            col1, col2 = st.columns(2)
            
            with col1:
                st.markdown("<h3 style='color: #f8fafc;'>📁 File Status Distribution</h3>", unsafe_allow_html=True)
                file_data = {
                    'Status': ['Completed', 'Pending', 'Processing', 'Failed'],
                    'Count': [
                        stats['files']['completed'],
                        stats['files']['pending'],
                        stats['files']['processing'],
                        stats['files']['failed']
                    ]
                }
                colors = ['#10b981', '#f59e0b', '#6366f1', '#ef4444']
                fig = px.pie(file_data, values='Count', names='Status', 
                           color_discrete_sequence=colors)
                fig.update_layout(
                    paper_bgcolor='rgba(0,0,0,0)',
                    plot_bgcolor='rgba(0,0,0,0)',
                    font_color='#f8fafc'
                )
                st.plotly_chart(fig, use_container_width=True)
            
            with col2:
                st.markdown("<h3 style='color: #f8fafc;'>🏷️ Top PII Entity Types</h3>", unsafe_allow_html=True)
                if stats['pii_stats']['top_entity_types']:
                    entities = [e[0] for e in stats['pii_stats']['top_entity_types'][:8]]
                    counts = [e[1] for e in stats['pii_stats']['top_entity_types'][:8]]
                    fig = px.bar(x=entities, y=counts, 
                               color=entities,
                               color_discrete_sequence=px.colors.sequential.Plasma)
                    fig.update_layout(
                        paper_bgcolor='rgba(0,0,0,0)',
                        plot_bgcolor='rgba(0,0,0,0)',
                        font_color='#f8fafc',
                        xaxis_title="Entity Type",
                        yaxis_title="Count",
                        showlegend=False
                    )
                    st.plotly_chart(fig, use_container_width=True)
                else:
                    st.info("No PII data available yet")
            
            # Recent activity
            st.markdown("<h3 style='color: #f8fafc; margin-top: 30px;'>📈 Recent Activity</h3>", unsafe_allow_html=True)
            col1, col2 = st.columns(2)
            
            with col1:
                st.markdown(f"""
                <div class="pii-card">
                    <h4 style="color: #6366f1; margin: 0;">📤 Uploads (Last 7 Days)</h4>
                    <p style="font-size: 2rem; font-weight: 700; color: #f8fafc; margin: 10px 0;">
                        {stats['recent_activity']['uploads_last_7_days']}
                    </p>
                </div>
                """, unsafe_allow_html=True)
            
            with col2:
                st.markdown(f"""
                <div class="pii-card">
                    <h4 style="color: #ec4899; margin: 0;">🔐 Logins (Last 7 Days)</h4>
                    <p style="font-size: 2rem; font-weight: 700; color: #f8fafc; margin: 10px 0;">
                        {stats['recent_activity']['logins_last_7_days']}
                    </p>
                </div>
                """, unsafe_allow_html=True)
        else:
            st.error("Failed to fetch statistics")
    else:
        # Standard user dashboard
        st.info("👋 Welcome! Use the Text Analyzer to check text for PII, or browse available files.")
        
        col1, col2 = st.columns(2)
        with col1:
            st.markdown("""
            <div class="pii-card">
                <h3 style="color: #6366f1;">🔍 Text Analyzer</h3>
                <p style="color: #94a3b8;">Paste text to detect and sanitize PII in real-time</p>
            </div>
            """, unsafe_allow_html=True)
        
        with col2:
            st.markdown("""
            <div class="pii-card">
                <h3 style="color: #ec4899;">📁 Files</h3>
                <p style="color: #94a3b8;">View and download sanitized files</p>
            </div>
            """, unsafe_allow_html=True)


# ==================== Text Analyzer Page ====================

elif page == "🔍 Text Analyzer":
    st.markdown("""
    <div style="margin-bottom: 30px;">
        <h1 style="color: #f8fafc; margin: 0;">🔍 Text Analyzer</h1>
        <p style="color: #94a3b8;">Real-time PII detection and sanitization</p>
    </div>
    """, unsafe_allow_html=True)
    
    # Fetch entity colors
    if not st.session_state.entity_colors:
        fetch_entity_colors()
    
    tab1, tab2, tab3 = st.tabs(["✨ Quick Analysis", "🔄 Compare Modes", "📊 Batch Analysis"])
    
    with tab1:
        col1, col2 = st.columns([1, 1])
        
        with col1:
            st.markdown("<h3 style='color: #f8fafc;'>📝 Input Text</h3>", unsafe_allow_html=True)
            input_text = st.text_area(
                "Enter text to analyze",
                height=300,
                placeholder="Paste your text here... Example:\nMy name is John Doe and my email is john.doe@email.com.\nI live at 123 Main Street, Mumbai 400001.\nMy phone number is +91 98765 43210.",
                label_visibility="collapsed"
            )
            
            mode = st.selectbox(
                "Sanitization Mode",
                [("mask", "🔒 Mask - Partial replacement"), 
                 ("redact", "🚫 Redact - Full replacement"),
                 ("tokenize", "🎫 Tokenize - Stable tokens")],
                format_func=lambda x: x[1]
            )
            
            analyze_btn = st.button("🔍 Analyze Text", use_container_width=True)
        
        with col2:
            st.markdown("<h3 style='color: #f8fafc;'>📊 Results</h3>", unsafe_allow_html=True)
            
            if analyze_btn and input_text:
                with st.spinner("Analyzing..."):
                    response = requests.post(
                        f"{API_URL}/analysis/text",
                        json={"text": input_text, "mode": mode[0]},
                        headers=get_headers()
                    )
                    
                    if response.status_code == 200:
                        result = response.json()
                        
                        # Entity counts
                        if result['entity_counts']:
                            st.markdown("<h4 style='color: #6366f1;'>Detected Entities:</h4>", unsafe_allow_html=True)
                            cols = st.columns(3)
                            idx = 0
                            for entity, count in result['entity_counts'].items():
                                with cols[idx % 3]:
                                    color = get_entity_color(entity)
                                    st.markdown(f"""
                                    <div style="background: {color}20; border: 1px solid {color}; 
                                                border-radius: 8px; padding: 10px; text-align: center; margin: 5px 0;">
                                        <span style="color: {color}; font-weight: 600;">{entity}</span>
                                        <span style="color: #f8fafc; font-size: 1.5rem; font-weight: 700; display: block;">
                                            {count}
                                        </span>
                                    </div>
                                    """, unsafe_allow_html=True)
                                idx += 1
                        else:
                            st.success("✅ No PII detected in the text!")
                        
                        # Sanitized output
                        st.markdown("<h4 style='color: #ec4899; margin-top: 20px;'>Sanitized Output:</h4>", unsafe_allow_html=True)
                        st.code(result['sanitized_text'], language="text")
                        
                        # Detailed detections
                        if result['detections']:
                            with st.expander("🔍 View Detailed Detections"):
                                for det in result['detections']:
                                    color = get_entity_color(det['entity_type'])
                                    st.markdown(f"""
                                    <div style="background: #1e293b; border-left: 4px solid {color}; 
                                                padding: 12px; margin: 8px 0; border-radius: 0 8px 8px 0;">
                                        <span style="background: {color}; color: white; padding: 2px 8px; 
                                                    border-radius: 4px; font-size: 0.75rem; font-weight: 600;">
                                            {det['entity_type']}
                                        </span>
                                        <span style="color: #f8fafc; margin-left: 10px; font-family: monospace;">
                                            "{det['text']}"
                                        </span>
                                        <span style="color: #94a3b8; float: right;">
                                            Confidence: {det['confidence']:.0%}
                                        </span>
                                    </div>
                                    """, unsafe_allow_html=True)
                    else:
                        st.error("Failed to analyze text")
            else:
                st.info("Enter text and click 'Analyze Text' to see results")
    
    with tab2:
        st.markdown("<h3 style='color: #f8fafc;'>🔄 Compare All Sanitization Modes</h3>", unsafe_allow_html=True)
        
        compare_text = st.text_area(
            "Enter text to compare",
            height=150,
            placeholder="Enter text to see how different sanitization modes work...",
            key="compare_input"
        )
        
        if st.button("🔄 Compare Modes", use_container_width=True) and compare_text:
            with st.spinner("Comparing modes..."):
                response = requests.post(
                    f"{API_URL}/analysis/compare",
                    json={"text": compare_text},
                    headers=get_headers()
                )
                
                if response.status_code == 200:
                    result = response.json()
                    
                    # Show comparison
                    col1, col2, col3, col4 = st.columns(4)
                    
                    with col1:
                        st.markdown("""
                        <div style="background: #1e293b; border-radius: 12px; padding: 16px; height: 100%;">
                            <h4 style="color: #94a3b8; margin: 0;">📝 Original</h4>
                            <hr style="border-color: #334155;">
                            <p style="color: #f8fafc; font-family: monospace; font-size: 0.9rem;">
                        """, unsafe_allow_html=True)
                        st.code(result['original_text'], language="text")
                        st.markdown("</p></div>", unsafe_allow_html=True)
                    
                    with col2:
                        st.markdown("""
                        <div style="background: #1e293b; border-radius: 12px; padding: 16px; height: 100%; border: 2px solid #6366f1;">
                            <h4 style="color: #6366f1; margin: 0;">🔒 Mask</h4>
                            <hr style="border-color: #334155;">
                        """, unsafe_allow_html=True)
                        st.code(result['mask_version'], language="text")
                        st.markdown("</div>", unsafe_allow_html=True)
                    
                    with col3:
                        st.markdown("""
                        <div style="background: #1e293b; border-radius: 12px; padding: 16px; height: 100%; border: 2px solid #ef4444;">
                            <h4 style="color: #ef4444; margin: 0;">🚫 Redact</h4>
                            <hr style="border-color: #334155;">
                        """, unsafe_allow_html=True)
                        st.code(result['redact_version'], language="text")
                        st.markdown("</div>", unsafe_allow_html=True)
                    
                    with col4:
                        st.markdown("""
                        <div style="background: #1e293b; border-radius: 12px; padding: 16px; height: 100%; border: 2px solid #10b981;">
                            <h4 style="color: #10b981; margin: 0;">🎫 Tokenize</h4>
                            <hr style="border-color: #334155;">
                        """, unsafe_allow_html=True)
                        st.code(result['tokenize_version'], language="text")
                        st.markdown("</div>", unsafe_allow_html=True)
                    
                    # Entity summary
                    if result['entity_counts']:
                        st.markdown("<h4 style='color: #f8fafc; margin-top: 20px;'>📊 Entities Detected:</h4>", unsafe_allow_html=True)
                        for entity, count in result['entity_counts'].items():
                            color = get_entity_color(entity)
                            st.markdown(f"""
                            <span style="background: {color}; color: white; padding: 4px 12px; 
                                        border-radius: 20px; font-size: 0.8rem; font-weight: 600; margin: 2px;">
                                {entity}: {count}
                            </span>
                            """, unsafe_allow_html=True)
                else:
                    st.error("Failed to compare modes")
    
    with tab3:
        st.markdown("<h3 style='color: #f8fafc;'>📊 Batch Analysis</h3>", unsafe_allow_html=True)
        st.info("Enter multiple texts (one per line) to analyze them all at once")
        
        batch_text = st.text_area(
            "Enter texts (one per line)",
            height=200,
            placeholder="Text 1 with PII...\nText 2 with PII...\nText 3 with PII...",
            key="batch_input"
        )
        
        batch_mode = st.selectbox(
            "Mode",
            [("mask", "🔒 Mask"), ("redact", "🚫 Redact"), ("tokenize", "🎫 Tokenize")],
            format_func=lambda x: x[1],
            key="batch_mode"
        )
        
        if st.button("📊 Analyze Batch", use_container_width=True) and batch_text:
            texts = [t.strip() for t in batch_text.split('\n') if t.strip()]
            
            with st.spinner(f"Analyzing {len(texts)} texts..."):
                response = requests.post(
                    f"{API_URL}/analysis/batch",
                    json={"texts": texts, "mode": batch_mode[0]},
                    headers=get_headers()
                )
                
                if response.status_code == 200:
                    result = response.json()
                    
                    # Summary
                    st.markdown(f"""
                    <div style="background: linear-gradient(135deg, #6366f1 0%, #8b5cf6 100%); 
                                border-radius: 12px; padding: 20px; margin: 20px 0;">
                        <h4 style="color: white; margin: 0;">📈 Batch Summary</h4>
                        <div style="display: flex; justify-content: space-around; margin-top: 15px;">
                            <div style="text-align: center;">
                                <p style="font-size: 2rem; font-weight: 700; color: white; margin: 0;">
                                    {result['summary']['total_texts']}
                                </p>
                                <p style="color: rgba(255,255,255,0.8); margin: 0;">Texts Analyzed</p>
                            </div>
                            <div style="text-align: center;">
                                <p style="font-size: 2rem; font-weight: 700; color: white; margin: 0;">
                                    {result['summary']['total_entities_detected']}
                                </p>
                                <p style="color: rgba(255,255,255,0.8); margin: 0;">Total Entities</p>
                            </div>
                            <div style="text-align: center;">
                                <p style="font-size: 2rem; font-weight: 700; color: white; margin: 0;">
                                    {result['summary']['average_entities_per_text']:.1f}
                                </p>
                                <p style="color: rgba(255,255,255,0.8); margin: 0;">Avg per Text</p>
                            </div>
                        </div>
                    </div>
                    """, unsafe_allow_html=True)
                    
                    # Individual results
                    for i, res in enumerate(result['results'], 1):
                        with st.expander(f"📄 Text {i} - {res['total_entities']} entities"):
                            col1, col2 = st.columns(2)
                            with col1:
                                st.markdown("<p style='color: #94a3b8;'>📝 Original:</p>", unsafe_allow_html=True)
                                st.code(res['original_text'][:200] + "..." if len(res['original_text']) > 200 else res['original_text'], language="text")
                            with col2:
                                st.markdown("<p style='color: #94a3b8;'>🔒 Sanitized:</p>", unsafe_allow_html=True)
                                st.code(res['sanitized_text'][:200] + "..." if len(res['sanitized_text']) > 200 else res['sanitized_text'], language="text")
                            
                            if res['entity_counts']:
                                st.markdown("<p style='color: #f8fafc;'>Entities:</p>", unsafe_allow_html=True)
                                for entity, count in res['entity_counts'].items():
                                    color = get_entity_color(entity)
                                    st.markdown(f"""
                                    <span style="background: {color}; color: white; padding: 2px 8px; 
                                                border-radius: 12px; font-size: 0.7rem; margin: 2px;">
                                        {entity}: {count}
                                    </span>
                                    """, unsafe_allow_html=True)
                else:
                    st.error("Failed to analyze batch")


# ==================== Files Page ====================

elif page == "📁 Files":
    st.markdown("""
    <div style="margin-bottom: 30px;">
        <h1 style="color: #f8fafc; margin: 0;">📁 Files</h1>
        <p style="color: #94a3b8;">Browse and download sanitized files</p>
    </div>
    """, unsafe_allow_html=True)
    
    response = requests.get(f"{API_URL}/files/", headers=get_headers())
    
    if response.status_code == 200:
        files = response.json()
        
        if not files:
            st.info("📭 No files available")
        else:
            # Search and filter
            search = st.text_input("🔍 Search files", placeholder="Enter filename...")
            
            filtered_files = files
            if search:
                filtered_files = [f for f in files if search.lower() in f['original_filename'].lower()]
            
            st.markdown(f"<p style='color: #94a3b8;'>Showing {len(filtered_files)} files</p>", unsafe_allow_html=True)
            
            for file in filtered_files:
                status_color = "#10b981" if file['status'] == 'completed' else "#f59e0b" if file['status'] == 'processing' else "#ef4444"
                
                with st.expander(f"📄 {file['original_filename']}"):
                    st.markdown(f"""
                    <div style="background: #1e293b; border-radius: 12px; padding: 16px;">
                        <div style="display: grid; grid-template-columns: repeat(3, 1fr); gap: 16px;">
                            <div>
                                <p style="color: #94a3b8; margin: 0; font-size: 0.8rem;">Type</p>
                                <p style="color: #f8fafc; margin: 0; font-weight: 600;">{file['file_type'].upper()}</p>
                            </div>
                            <div>
                                <p style="color: #94a3b8; margin: 0; font-size: 0.8rem;">Size</p>
                                <p style="color: #f8fafc; margin: 0; font-weight: 600;">{file['file_size']:,} bytes</p>
                            </div>
                            <div>
                                <p style="color: #94a3b8; margin: 0; font-size: 0.8rem;">Status</p>
                                <p style="color: {status_color}; margin: 0; font-weight: 600;">● {file['status'].upper()}</p>
                            </div>
                        </div>
                        <div style="margin-top: 16px;">
                            <p style="color: #94a3b8; margin: 0; font-size: 0.8rem;">Mode</p>
                            <p style="color: #f8fafc; margin: 0;">{file['anonymization_mode'] or 'N/A'}</p>
                        </div>
                        <div style="margin-top: 16px;">
                            <p style="color: #94a3b8; margin: 0; font-size: 0.8rem;">Uploaded</p>
                            <p style="color: #f8fafc; margin: 0;">{file['created_at'][:19] if file['created_at'] else 'N/A'}</p>
                        </div>
                    </div>
                    """, unsafe_allow_html=True)
                    
                    if file['entity_counts']:
                        st.markdown("<p style='color: #f8fafc; margin-top: 16px;'>🏷️ PII Detected:</p>", unsafe_allow_html=True)
                        cols = st.columns(4)
                        idx = 0
                        for entity, count in file['entity_counts'].items():
                            with cols[idx % 4]:
                                color = get_entity_color(entity)
                                st.markdown(f"""
                                <div style="background: {color}20; border: 1px solid {color}; 
                                            border-radius: 8px; padding: 8px; text-align: center;">
                                    <span style="color: {color}; font-size: 0.7rem; font-weight: 600;">{entity}</span>
                                    <span style="color: #f8fafc; font-size: 1.2rem; font-weight: 700; display: block;">{count}</span>
                                </div>
                                """, unsafe_allow_html=True)
                            idx += 1
                    
                    col1, col2, col3 = st.columns(3)
                    
                    with col1:
                        if file['status'] == 'completed':
                            if st.button("⬇️ Download", key=f"dl_{file['id']}", use_container_width=True):
                                dl_response = requests.get(
                                    f"{API_URL}/files/{file['id']}/download",
                                    headers=get_headers()
                                )
                                if dl_response.status_code == 200:
                                    st.download_button(
                                        label="💾 Save File",
                                        data=dl_response.content,
                                        file_name=f"sanitized_{file['original_filename']}",
                                        mime="application/octet-stream",
                                        key=f"save_{file['id']}",
                                        use_container_width=True
                                    )
                    
                    with col2:
                        if st.button("👁️ Preview", key=f"preview_{file['id']}", use_container_width=True):
                            preview_response = requests.get(
                                f"{API_URL}/files/{file['id']}/preview",
                                headers=get_headers()
                            )
                            if preview_response.status_code == 200:
                                preview_data = preview_response.json()
                                st.text_area(
                                    "Preview",
                                    preview_data['content'],
                                    height=200,
                                    key=f"preview_content_{file['id']}"
                                )
                                if preview_data.get('truncated'):
                                    st.info("Content truncated for preview")
                    
                    with col3:
                        if st.session_state.user['role'] == 'admin':
                            if st.button("📥 Original", key=f"orig_{file['id']}", use_container_width=True):
                                orig_response = requests.get(
                                    f"{API_URL}/files/{file['id']}/original",
                                    headers=get_headers()
                                )
                                if orig_response.status_code == 200:
                                    st.download_button(
                                        label="💾 Save Original",
                                        data=orig_response.content,
                                        file_name=file['original_filename'],
                                        mime="application/octet-stream",
                                        key=f"dl_orig_{file['id']}",
                                        use_container_width=True
                                    )
    else:
        st.error("Failed to fetch files")


# ==================== Upload Page (Admin Only) ====================

elif page == "⬆️ Upload" and st.session_state.user['role'] == 'admin':
    st.markdown("""
    <div style="margin-bottom: 30px;">
        <h1 style="color: #f8fafc; margin: 0;">⬆️ Upload File</h1>
        <p style="color: #94a3b8;">Upload files for PII detection and sanitization</p>
    </div>
    """, unsafe_allow_html=True)
    
    with st.form("upload_form"):
        uploaded_file = st.file_uploader(
            "Choose a file",
            type=['sql', 'pdf', 'docx', 'csv', 'json', 'txt'],
            help="Supported formats: SQL, PDF, DOCX, CSV, JSON, TXT"
        )
        
        mode = st.selectbox(
            "Sanitization Mode",
            [
                ("mask", "🔒 Mask - Partial replacement (Recommended)"),
                ("redact", "🚫 Redact - Full replacement"),
                ("tokenize", "🎫 Tokenize - Stable tokens")
            ],
            format_func=lambda x: x[1]
        )
        
        submit = st.form_submit_button("🚀 Upload & Process", use_container_width=True)
        
        if submit and uploaded_file:
            with st.spinner("Processing file..."):
                files = {"file": (uploaded_file.name, uploaded_file.getvalue(), uploaded_file.type)}
                data = {"mode": mode[0]}
                
                response = requests.post(
                    f"{API_URL}/files/upload",
                    files=files,
                    data=data,
                    headers=get_headers()
                )
                
                if response.status_code == 200:
                    result = response.json()
                    
                    st.success("✅ File processed successfully!")
                    
                    st.markdown(f"""
                    <div style="background: linear-gradient(135deg, #10b981 0%, #059669 100%); 
                                border-radius: 12px; padding: 24px; margin: 20px 0;">
                        <h3 style="color: white; margin: 0;">📊 Processing Results</h3>
                        <div style="display: flex; justify-content: space-around; margin-top: 20px;">
                            <div style="text-align: center;">
                                <p style="font-size: 3rem; font-weight: 700; color: white; margin: 0;">
                                    {result['total_entities']}
                                </p>
                                <p style="color: rgba(255,255,255,0.9); margin: 0;">Total Entities Found</p>
                            </div>
                        </div>
                    </div>
                    """, unsafe_allow_html=True)
                    
                    if result['entity_counts']:
                        st.markdown("<h4 style='color: #f8fafc;'>🏷️ Entity Breakdown:</h4>", unsafe_allow_html=True)
                        cols = st.columns(4)
                        idx = 0
                        for entity, count in result['entity_counts'].items():
                            with cols[idx % 4]:
                                color = get_entity_color(entity)
                                st.markdown(f"""
                                <div style="background: {color}20; border: 1px solid {color}; 
                                            border-radius: 8px; padding: 12px; text-align: center;">
                                    <span style="color: {color}; font-weight: 600;">{entity}</span>
                                    <span style="color: #f8fafc; font-size: 1.5rem; font-weight: 700; display: block;">
                                        {count}
                                    </span>
                                </div>
                                """, unsafe_allow_html=True)
                            idx += 1
                else:
                    st.error(f"❌ Upload failed: {response.text}")


# ==================== Analytics Page (Admin Only) ====================

elif page == "📈 Analytics" and st.session_state.user['role'] == 'admin':
    st.markdown("""
    <div style="margin-bottom: 30px;">
        <h1 style="color: #f8fafc; margin: 0;">📈 Analytics</h1>
        <p style="color: #94a3b8;">Detailed system analytics and trends</p>
    </div>
    """, unsafe_allow_html=True)
    
    tab1, tab2, tab3 = st.tabs(["📊 Trends", "👥 User Activity", "📋 System Stats"])
    
    with tab1:
        days = st.slider("Time Period (Days)", 7, 90, 30)
        
        response = requests.get(f"{API_URL}/admin/pii-trends?days={days}", headers=get_headers())
        if response.status_code == 200:
            trends = response.json()
            
            if trends['daily_data']:
                dates = [d['date'] for d in trends['daily_data']]
                files = [d['files_processed'] for d in trends['daily_data']]
                entities = [d['entities_detected'] for d in trends['daily_data']]
                
                # Create subplot
                fig = make_subplots(rows=2, cols=1, subplot_titles=('Files Processed', 'Entities Detected'))
                
                fig.add_trace(
                    go.Scatter(x=dates, y=files, mode='lines+markers', 
                              line=dict(color='#6366f1', width=3),
                              marker=dict(size=8)),
                    row=1, col=1
                )
                
                fig.add_trace(
                    go.Scatter(x=dates, y=entities, mode='lines+markers',
                              line=dict(color='#ec4899', width=3),
                              marker=dict(size=8)),
                    row=2, col=1
                )
                
                fig.update_layout(
                    height=600,
                    paper_bgcolor='rgba(0,0,0,0)',
                    plot_bgcolor='rgba(0,0,0,0)',
                    font_color='#f8fafc',
                    showlegend=False
                )
                
                st.plotly_chart(fig, use_container_width=True)
            else:
                st.info("No trend data available for the selected period")
        else:
            st.error("Failed to fetch trends")
    
    with tab2:
        response = requests.get(f"{API_URL}/admin/user-activity", headers=get_headers())
        if response.status_code == 200:
            activity = response.json()
            
            if activity['activities']:
                for act in activity['activities']:
                    success_icon = "✅" if act['success'] else "❌"
                    st.markdown(f"""
                    <div style="background: #1e293b; border-radius: 8px; padding: 12px; margin: 8px 0;">
                        <div style="display: flex; justify-content: space-between; align-items: center;">
                            <span style="color: #f8fafc; font-weight: 600;">{success_icon} {act['event_type']}</span>
                            <span style="color: #94a3b8; font-size: 0.8rem;">{act['timestamp'][:19] if act['timestamp'] else 'N/A'}</span>
                        </div>
                        <p style="color: #94a3b8; margin: 4px 0 0 0; font-size: 0.9rem;">
                            User: <strong style="color: #6366f1;">{act['username']}</strong>
                            {f" | File: {act['filename']}" if act['filename'] else ""}
                        </p>
                    </div>
                    """, unsafe_allow_html=True)
            else:
                st.info("No activity recorded yet")
        else:
            st.error("Failed to fetch user activity")
    
    with tab3:
        response = requests.get(f"{API_URL}/admin/stats", headers=get_headers())
        if response.status_code == 200:
            stats = response.json()
            
            col1, col2 = st.columns(2)
            
            with col1:
                st.markdown("<h3 style='color: #f8fafc;'>👥 Users</h3>", unsafe_allow_html=True)
                user_data = {
                    'Type': ['Admins', 'Standard', 'Active', 'Inactive'],
                    'Count': [
                        stats['users']['admins'],
                        stats['users']['standard'],
                        stats['users']['active'],
                        stats['users']['total'] - stats['users']['active']
                    ]
                }
                fig = px.bar(user_data, x='Type', y='Count', 
                           color='Type', color_discrete_sequence=['#6366f1', '#ec4899', '#10b981', '#ef4444'])
                fig.update_layout(
                    paper_bgcolor='rgba(0,0,0,0)',
                    plot_bgcolor='rgba(0,0,0,0)',
                    font_color='#f8fafc',
                    showlegend=False
                )
                st.plotly_chart(fig, use_container_width=True)
            
            with col2:
                st.markdown("<h3 style='color: #f8fafc;'>📁 File Types</h3>", unsafe_allow_html=True)
                if stats['file_types']:
                    fig = px.pie(
                        values=list(stats['file_types'].values()),
                        names=list(stats['file_types'].keys()),
                        color_discrete_sequence=px.colors.sequential.Plasma
                    )
                    fig.update_layout(
                        paper_bgcolor='rgba(0,0,0,0)',
                        plot_bgcolor='rgba(0,0,0,0)',
                        font_color='#f8fafc'
                    )
                    st.plotly_chart(fig, use_container_width=True)
                else:
                    st.info("No file type data available")
        else:
            st.error("Failed to fetch stats")


# ==================== Users Page (Admin Only) ====================

elif page == "👥 Users" and st.session_state.user['role'] == 'admin':
    st.markdown("""
    <div style="margin-bottom: 30px;">
        <h1 style="color: #f8fafc; margin: 0;">👥 User Management</h1>
        <p style="color: #94a3b8;">Manage system users and permissions</p>
    </div>
    """, unsafe_allow_html=True)
    
    tab1, tab2 = st.tabs(["📋 Users List", "➕ Create User"])
    
    with tab1:
        response = requests.get(f"{API_URL}/admin/users", headers=get_headers())
        
        if response.status_code == 200:
            users = response.json()
            
            for user in users:
                status_color = "#10b981" if user['is_active'] else "#ef4444"
                role_gradient = "linear-gradient(135deg, #f59e0b 0%, #d97706 100%)" if user['role'] == 'admin' else "linear-gradient(135deg, #6366f1 0%, #8b5cf6 100%)"
                
                with st.expander(f"{'🟢' if user['is_active'] else '🔴'} {'👑' if user['role'] == 'admin' else '👤'} {user['username']}"):
                    st.markdown(f"""
                    <div style="background: #1e293b; border-radius: 12px; padding: 20px;">
                        <div style="display: grid; grid-template-columns: repeat(2, 1fr); gap: 20px;">
                            <div>
                                <p style="color: #94a3b8; margin: 0; font-size: 0.8rem;">Username</p>
                                <p style="color: #f8fafc; margin: 0; font-weight: 600; font-size: 1.1rem;">{user['username']}</p>
                            </div>
                            <div>
                                <p style="color: #94a3b8; margin: 0; font-size: 0.8rem;">Email</p>
                                <p style="color: #f8fafc; margin: 0;">{user['email']}</p>
                            </div>
                            <div>
                                <p style="color: #94a3b8; margin: 0; font-size: 0.8rem;">Role</p>
                                <span style="background: {role_gradient}; color: white; padding: 4px 12px; 
                                            border-radius: 20px; font-size: 0.8rem; font-weight: 600;">
                                    {user['role'].upper()}
                                </span>
                            </div>
                            <div>
                                <p style="color: #94a3b8; margin: 0; font-size: 0.8rem;">Status</p>
                                <span style="color: {status_color}; font-weight: 600;">
                                    {'● Active' if user['is_active'] else '● Inactive'}
                                </span>
                            </div>
                        </div>
                        <div style="margin-top: 16px;">
                            <p style="color: #94a3b8; margin: 0; font-size: 0.8rem;">Created</p>
                            <p style="color: #f8fafc; margin: 0;">{user['created_at'][:19] if user['created_at'] else 'N/A'}</p>
                        </div>
                    </div>
                    """, unsafe_allow_html=True)
                    
                    if user['id'] != st.session_state.user['id'] and user['is_active']:
                        if st.button("🗑️ Deactivate", key=f"deactivate_{user['id']}", use_container_width=True):
                            del_response = requests.delete(
                                f"{API_URL}/admin/users/{user['id']}",
                                headers=get_headers()
                            )
                            if del_response.status_code == 200:
                                st.success("✅ User deactivated")
                                st.rerun()
                            else:
                                st.error("❌ Failed to deactivate user")
    
    with tab2:
        with st.form("create_user_form"):
            st.markdown("<h3 style='color: #f8fafc;'>Create New User</h3>", unsafe_allow_html=True)
            
            new_username = st.text_input("Username", placeholder="Enter username")
            new_email = st.text_input("Email", placeholder="Enter email address")
            new_password = st.text_input("Password", type="password", placeholder="Enter secure password")
            new_role = st.selectbox(
                "Role",
                [("standard", "👤 Standard User"), ("admin", "👑 Admin")],
                format_func=lambda x: x[1]
            )
            
            submit = st.form_submit_button("➕ Create User", use_container_width=True)
            
            if submit:
                user_data = {
                    "username": new_username,
                    "email": new_email,
                    "password": new_password,
                    "role": new_role[0]
                }
                
                response = requests.post(
                    f"{API_URL}/admin/users",
                    json=user_data,
                    headers=get_headers()
                )
                
                if response.status_code == 200:
                    st.success("✅ User created successfully!")
                else:
                    st.error(f"❌ Failed to create user: {response.text}")


# ==================== Audit Logs Page (Admin Only) ====================

elif page == "📋 Audit Logs" and st.session_state.user['role'] == 'admin':
    st.markdown("""
    <div style="margin-bottom: 30px;">
        <h1 style="color: #f8fafc; margin: 0;">📋 Audit Logs</h1>
        <p style="color: #94a3b8;">System activity and security logs</p>
    </div>
    """, unsafe_allow_html=True)
    
    # Filters
    col1, col2 = st.columns(2)
    with col1:
        event_filter = st.selectbox(
            "Filter by Event Type",
            ["All", "FILE_UPLOAD", "FILE_DOWNLOAD_SANITIZED", "FILE_DOWNLOAD_ORIGINAL", 
             "FILE_VIEW_ORIGINAL", "PII_DETECTED", "SANITIZATION_COMPLETED", "USER_LOGIN", "USER_CREATED"]
        )
    with col2:
        user_filter = st.text_input("Filter by Username", placeholder="Enter username...")
    
    # Fetch logs
    params = {}
    if event_filter != "All":
        params["event_type"] = event_filter
    if user_filter:
        params["username"] = user_filter
    
    response = requests.get(f"{API_URL}/admin/audit-logs", params=params, headers=get_headers())
    
    if response.status_code == 200:
        logs = response.json()
        
        if not logs:
            st.info("📭 No audit logs found")
        else:
            st.markdown(f"<p style='color: #94a3b8;'>Showing {len(logs)} log entries</p>", unsafe_allow_html=True)
            
            for log in logs:
                success_color = "#10b981" if log['success'] else "#ef4444"
                
                with st.expander(f"{'✅' if log['success'] else '❌'} {log['event_type']} - {log['username']}"):
                    st.markdown(f"""
                    <div style="background: #1e293b; border-radius: 12px; padding: 20px;">
                        <div style="display: grid; grid-template-columns: repeat(2, 1fr); gap: 16px;">
                            <div>
                                <p style="color: #94a3b8; margin: 0; font-size: 0.8rem;">User</p>
                                <p style="color: #f8fafc; margin: 0; font-weight: 600;">{log['username']}</p>
                                <p style="color: #6366f1; margin: 0; font-size: 0.8rem;">{log['user_role']}</p>
                            </div>
                            <div>
                                <p style="color: #94a3b8; margin: 0; font-size: 0.8rem;">Timestamp</p>
                                <p style="color: #f8fafc; margin: 0;">{log['timestamp'][:19] if log['timestamp'] else 'N/A'}</p>
                            </div>
                            <div>
                                <p style="color: #94a3b8; margin: 0; font-size: 0.8rem;">Event</p>
                                <p style="color: #f8fafc; margin: 0;">{log['event_type']}</p>
                            </div>
                            <div>
                                <p style="color: #94a3b8; margin: 0; font-size: 0.8rem;">Status</p>
                                <span style="color: {success_color}; font-weight: 600;">
                                    {'✅ Success' if log['success'] else '❌ Failed'}
                                </span>
                            </div>
                        </div>
                        
                        {f'<div style="margin-top: 16px;"><p style="color: #94a3b8; margin: 0; font-size: 0.8rem;">File</p><p style="color: #f8fafc; margin: 0;">{log["filename"]}</p></div>' if log['filename'] else ''}
                        
                        {f'<div style="margin-top: 16px;"><p style="color: #94a3b8; margin: 0; font-size: 0.8rem;">Mode</p><p style="color: #f8fafc; margin: 0;">{log["anonymization_mode"]}</p></div>' if log['anonymization_mode'] else ''}
                        
                        {f'<div style="margin-top: 16px;"><p style="color: #94a3b8; margin: 0; font-size: 0.8rem;">Entities</p><p style="color: #f8fafc; margin: 0;">{log["entity_counts"]}</p></div>' if log['entity_counts'] else ''}
                        
                        {f'<div style="margin-top: 16px; background: rgba(239, 68, 68, 0.1); border: 1px solid rgba(239, 68, 68, 0.3); border-radius: 8px; padding: 12px;"><p style="color: #ef4444; margin: 0;"><strong>Error:</strong> {log["error_message"]}</p></div>' if log['error_message'] else ''}
                    </div>
                    """, unsafe_allow_html=True)
    else:
        st.error("Failed to fetch audit logs")