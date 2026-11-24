
import streamlit as st
import sqlite3
import hashlib
import secrets
import hmac
import re

from pathlib import Path
from transformers import pipeline
from PyPDF2 import PdfReader


# =====================================================
# 1. PAGE CONFIGURATION
# =====================================================

st.set_page_config(
    page_title="ReportAI",
    page_icon="📘",
    layout="wide",
    initial_sidebar_state="expanded"
)


# =====================================================
# 2. DATABASE CONFIGURATION
# =====================================================

DB_PATH = Path(__file__).parent / "reportai_users.db"

HASH_ITERATIONS = 600000


def get_connection():

    return sqlite3.connect(DB_PATH)


def create_database():

    conn = get_connection()
    cursor = conn.cursor()

    cursor.execute("""
        CREATE TABLE IF NOT EXISTS users (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            username TEXT NOT NULL COLLATE NOCASE UNIQUE,
            salt BLOB NOT NULL,
            password_hash BLOB NOT NULL,
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
        )
    """)

    conn.commit()
    conn.close()


def hash_password(password, salt=None):

    if salt is None:
        salt = secrets.token_bytes(32)

    password_hash = hashlib.pbkdf2_hmac(
        "sha256",
        password.encode("utf-8"),
        salt,
        HASH_ITERATIONS
    )

    return salt, password_hash


def register_user(username, password):

    username = username.strip()

    salt, password_hash = hash_password(password)

    conn = get_connection()
    cursor = conn.cursor()

    try:

        cursor.execute("""
            INSERT INTO users (
                username,
                salt,
                password_hash
            )
            VALUES (?, ?, ?)
        """, (
            username,
            salt,
            password_hash
        ))

        conn.commit()

        return True, "Account created successfully!"

    except sqlite3.IntegrityError:

        return False, "Username already exists. Please choose another."

    finally:

        conn.close()


def verify_user(username, password):

    conn = get_connection()
    cursor = conn.cursor()

    try:

        cursor.execute("""
            SELECT salt, password_hash
            FROM users
            WHERE username = ?
        """, (username.strip(),))

        user = cursor.fetchone()

    finally:

        conn.close()

    if user is None:

        return False, "not_found"

    stored_salt, stored_hash = user

    _, entered_hash = hash_password(
        password,
        stored_salt
    )

    if hmac.compare_digest(
        stored_hash,
        entered_hash
    ):

        return True, "success"

    return False, "wrong_password"


# Create database automatically
create_database()


# =====================================================
# 3. LOAD CUSTOM CSS
# =====================================================

css_path = Path(__file__).parent / "style.css"

if css_path.exists():

    with open(css_path, "r", encoding="utf-8") as file:

        st.markdown(
            f"<style>{file.read()}</style>",
            unsafe_allow_html=True
        )


# =====================================================
# 4. SESSION STATE
# =====================================================

session_defaults = {
    "authenticated": False,
    "auth_page": "login",
    "logged_in_user": "",
    "report": "",
    "login_error": "",
    "registered_message": "",
    "pdf_text": ""
}

for key, value in session_defaults.items():

    if key not in st.session_state:

        st.session_state[key] = value


# =====================================================
# 5. AUTHENTICATION HEADER
# =====================================================

def show_auth_header():

    st.markdown("""
        <div class="login-header">
            <h1>ReportAI</h1>
            <p>Your Academic Writing Workspace</p>
        </div>
    """, unsafe_allow_html=True)


# =====================================================
# 6. LOGIN PAGE
# =====================================================

def show_login_page():

    show_auth_header()

    left, center, right = st.columns([1, 1, 1])

    with center:

        with st.container(border=True):

            st.markdown("""
                <div class="auth-avatar">♙</div>

                <div class="welcome-heading">
                    <h2>Welcome Back</h2>
                    <p>Login to your ReportAI account</p>
                </div>
            """, unsafe_allow_html=True)

            # Display successful registration message

            if st.session_state.registered_message:

                st.success(
                    st.session_state.registered_message
                )

                st.session_state.registered_message = ""

            # Login form

            with st.form("login_form"):

                username = st.text_input(
                    "Username",
                    placeholder="Enter your username"
                )

                password = st.text_input(
                    "Password",
                    placeholder="Enter your password",
                    type="password"
                )

                login_button = st.form_submit_button(
                    "LOGIN →",
                    use_container_width=True
                )

            if login_button:

                if not username.strip() or not password:

                    st.session_state.login_error = (
                        "Please enter both username and password."
                    )

                else:

                    success, message = verify_user(
                        username,
                        password
                    )

                    if success:

                        st.session_state.authenticated = True

                        st.session_state.logged_in_user = (
                            username.strip()
                        )

                        st.session_state.login_error = ""
                        st.session_state.report = ""

                        st.rerun()

                    elif message == "not_found":

                        st.session_state.login_error = (
                            "Account not found. Please sign up first."
                        )

                    else:

                        st.session_state.login_error = (
                            "Incorrect password. Please try again."
                        )

            if st.session_state.login_error:

                st.error(
                    st.session_state.login_error
                )

            st.markdown("---")

            st.markdown(
                """
                <p style="
                    text-align:center;
                    color:#999;
                    font-size:13px;
                ">
                    Don't have an account?
                </p>
                """,
                unsafe_allow_html=True
            )

            if st.button(
                "CREATE NEW ACCOUNT",
                use_container_width=True
            ):

                st.session_state.auth_page = "signup"
                st.session_state.login_error = ""

                st.rerun()

            st.markdown("""
                <p class="login-footer">
                    Your ideas. Your projects. One workspace.
                </p>
            """, unsafe_allow_html=True)


# =====================================================
# 7. SIGN UP PAGE
# =====================================================

def show_signup_page():

    show_auth_header()

    left, center, right = st.columns([1, 1, 1])

    with center:

        with st.container(border=True):

            st.markdown("""
                <div class="auth-avatar">♙</div>

                <div class="welcome-heading">
                    <h2>Create Account</h2>
                    <p>Join ReportAI and start your journey</p>
                </div>
            """, unsafe_allow_html=True)

            with st.form("signup_form"):

                username = st.text_input(
                    "Username",
                    placeholder="Choose a username"
                )

                password = st.text_input(
                    "Password",
                    placeholder="Create a password",
                    type="password"
                )

                confirm_password = st.text_input(
                    "Confirm Password",
                    placeholder="Re-enter your password",
                    type="password"
                )

                signup_button = st.form_submit_button(
                    "CREATE ACCOUNT →",
                    use_container_width=True
                )

            if signup_button:

                username = username.strip()

                if not username or not password or not confirm_password:

                    st.error(
                        "Please fill in all the fields."
                    )

                elif not re.fullmatch(
                    r"[A-Za-z0-9_.]{3,30}",
                    username
                ):

                    st.error(
                        "Username must be 3–30 characters. "
                        "Use letters, numbers, underscores or dots."
                    )

                elif len(password) < 8:

                    st.error(
                        "Password must contain at least 8 characters."
                    )

                elif len(password) > 128:

                    st.error(
                        "Password must not exceed 128 characters."
                    )

                elif password != confirm_password:

                    st.error(
                        "Passwords do not match."
                    )

                else:

                    success, message = register_user(
                        username,
                        password
                    )

                    if success:

                        st.session_state.registered_message = (
                            "Account created successfully! Please log in."
                        )

                        st.session_state.auth_page = "login"

                        st.rerun()

                    else:

                        st.error(message)

            st.markdown("---")

            st.markdown(
                """
                <p style="
                    text-align:center;
                    color:#999;
                    font-size:13px;
                ">
                    Already have an account?
                </p>
                """,
                unsafe_allow_html=True
            )

            if st.button(
                "BACK TO LOGIN",
                use_container_width=True
            ):

                st.session_state.auth_page = "login"

                st.rerun()

            st.markdown("""
                <p class="login-footer">
                    Create your account and start your journey.
                </p>
            """, unsafe_allow_html=True)


# =====================================================
# 8. DISPLAY LOGIN OR SIGNUP
# =====================================================

if not st.session_state.authenticated:

    if st.session_state.auth_page == "signup":

        show_signup_page()

    else:

        show_login_page()

    st.stop()


# =====================================================
# 9. LOAD AI MODEL
# =====================================================

@st.cache_resource
def load_model():

    return pipeline(
        "text2text-generation",
        model="google/flan-t5-base"
    )


def get_generator():

    with st.spinner("Loading AI model... Please wait."):

        return load_model()


# =====================================================
# 10. REPORT GENERATION PROMPTS
# =====================================================

SECTION_PROMPTS = {

    "Abstract": """
    Write an academic abstract for a college project titled
    '{topic}'.

    Explain the problem statement, proposed solution,
    technologies used and expected benefits.
    Use formal academic language.
    """,

    "Introduction": """
    Write an academic introduction for a college project titled
    '{topic}'.

    Explain the background, importance, existing challenges,
    problem statement and proposed solution.
    Use formal academic language.
    """,

    "Objectives": """
    Write the major and minor objectives for a college project
    titled '{topic}'.

    Present the objectives clearly in academic format.
    """,

    "Methodology": """
    Explain the step-by-step methodology for a college project
    titled '{topic}'.

    Include system design, data collection, implementation,
    technologies and testing.
    Use formal academic language.
    """,

    "Conclusion": """
    Write a formal academic conclusion for a project titled
    '{topic}'.

    Include project achievements, benefits, limitations
    and future enhancements.
    """
}


# =====================================================
# 11. GENERATE INDIVIDUAL SECTION
# =====================================================

def generate_section(generator, section, topic):

    prompt = SECTION_PROMPTS[section].format(
        topic=topic
    )

    result = generator(
        prompt,
        max_new_tokens=250,
        do_sample=False
    )

    return result[0]["generated_text"].strip()


# =====================================================
# 12. SIDEBAR
# =====================================================

with st.sidebar:

    st.markdown("## ✦ ReportAI")

    st.caption("Academic Writing Workspace")

    st.divider()

    st.write("👤 Logged in as")

    st.markdown(
        f"**{st.session_state.logged_in_user}**"
    )

    st.divider()

    st.markdown("### Your Workspace")

    st.write("📊 Dashboard")
    st.write("📝 Report Generator")
    st.write("📂 PDF Assistant")

    st.divider()

    if st.button(
        "🚪 Logout",
        use_container_width=True
    ):

        st.session_state.authenticated = False
        st.session_state.logged_in_user = ""
        st.session_state.report = ""
        st.session_state.pdf_text = ""
        st.session_state.auth_page = "login"
        st.session_state.login_error = ""

        st.rerun()

    st.divider()

    st.caption("ReportAI v1.0")


# =====================================================
# 13. MAIN DASHBOARD
# =====================================================

st.title("Welcome to ReportAI 👋")

st.write(
    f"Hello, **{st.session_state.logged_in_user}**! "
    "Create, edit and download your academic project reports."
)

st.divider()

st.subheader("📊 Your Workspace")

col1, col2, col3 = st.columns(3)

with col1:

    st.metric(
        "Report Sections",
        "5"
    )

with col2:

    st.metric(
        "AI Assistant",
        "Available"
    )

with col3:

    st.metric(
        "Document Support",
        "PDF"
    )


# =====================================================
# 14. PROJECT TITLE
# =====================================================

st.divider()

st.header("📝 Project Report Generator")

topic = st.text_input(
    "Enter your project title",
    placeholder="Example: AI Based Project Report Assistant"
)


# =====================================================
# 15. INDIVIDUAL SECTION GENERATION
# =====================================================

if topic:

    st.subheader("Generate Individual Sections")

    col1, col2, col3, col4, col5 = st.columns(5)

    section_columns = [
        ("Abstract", col1),
        ("Introduction", col2),
        ("Objectives", col3),
        ("Methodology", col4),
        ("Conclusion", col5)
    ]

    for section, column in section_columns:

        with column:

            if st.button(
                section,
                use_container_width=True,
                key=f"section_{section}"
            ):

                generator = get_generator()

                with st.spinner(
                    f"Generating {section}..."
                ):

                    generated_text = generate_section(
                        generator,
                        section,
                        topic
                    )

                    st.session_state.report += (
                        f"\n\n## {section}\n\n{generated_text}"
                    )

                st.success(
                    f"{section} generated successfully!"
                )


# =====================================================
# 16. GENERATE FULL REPORT
# =====================================================

if topic:

    st.divider()

    col6, col7 = st.columns(2)

    with col6:

        if st.button(
            "✨ Generate Full Report",
            use_container_width=True
        ):

            generator = get_generator()

            sections = []

            with st.spinner(
                "Generating complete report..."
            ):

                for section in SECTION_PROMPTS:

                    generated_text = generate_section(
                        generator,
                        section,
                        topic
                    )

                    sections.append(
                        f"## {section}\n\n{generated_text}"
                    )

                st.session_state.report = (
                    f"# {topic}\n\n"
                    + "\n\n".join(sections)
                )

            st.success(
                "Your complete report has been generated!"
            )

    with col7:

        if st.button(
            "🗑 Clear Report",
            use_container_width=True
        ):

            st.session_state.report = ""

            st.rerun()


# =====================================================
# 17. REPORT EDITOR
# =====================================================

st.divider()

st.header("📄 Final Project Report")

edited_report = st.text_area(
    "Edit your generated report here",
    value=st.session_state.report,
    height=450,
    placeholder="Your generated report will appear here..."
)

st.session_state.report = edited_report


# =====================================================
# 18. DOWNLOAD REPORT
# =====================================================

st.download_button(
    label="⬇ Download Project Report",
    data=edited_report,
    file_name="project_report.txt",
    mime="text/plain",
    use_container_width=True
)


# =====================================================
# 19. PDF UPLOAD
# =====================================================

st.divider()

st.header("📂 PDF Document Assistant")

st.write(
    "Upload a PDF document and ask questions based on its content."
)

uploaded_file = st.file_uploader(
    "Choose your PDF document",
    type=["pdf"]
)


# =====================================================
# 20. PDF QUESTION ANSWERING
# =====================================================

if uploaded_file is not None:

    try:

        reader = PdfReader(uploaded_file)

        pdf_text = ""

        for page in reader.pages:

            extracted_text = page.extract_text()

            if extracted_text:

                pdf_text += extracted_text + "\n"

        st.session_state.pdf_text = pdf_text

        if not pdf_text.strip():

            st.warning(
                "No readable text was found in this PDF."
            )

        else:

            st.success(
                "PDF uploaded successfully!"
            )

            st.subheader("📄 Document Preview")

            st.text_area(
                "PDF Content",
                value=pdf_text[:3000],
                height=200
            )

            question = st.text_input(
                "Ask a question about your PDF",
                key="pdf_question"
            )

            if st.button(
                "🔍 Get Answer",
                use_container_width=True
            ):

                if question.strip():

                    generator = get_generator()

                    prompt = f"""
                    Answer the question using only the information
                    in this document.

                    If the answer is not available, say that it
                    is not mentioned in the document.

                    Document:
                    {pdf_text[:3000]}

                    Question:
                    {question}
                    """

                    with st.spinner(
                        "Finding your answer..."
                    ):

                        result = generator(
                            prompt,
                            max_new_tokens=150,
                            do_sample=False
                        )

                        answer = result[0]["generated_text"].strip()

                    st.subheader("💡 Answer")

                    st.write(answer)

                else:

                    st.warning(
                        "Please enter a question first."
                    )

    except Exception as error:

        st.error(
            f"Error processing PDF: {error}"
        )


# =====================================================
# 21. FOOTER
# =====================================================

st.divider()

st.markdown("""
    <div style="
        text-align:center;
        color:#999;
        padding:15px;
    ">
        <b>ReportAI</b>
        <br>
        AI Powered Project Report Assistant
        <br>
        Built with Python, Streamlit, SQLite,
        FLAN-T5 and PyPDF2
    </div>
""", unsafe_allow_html=True)
