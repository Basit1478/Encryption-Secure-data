import streamlit as st # type: ignore
from cryptography.fernet import Fernet, InvalidToken # type: ignore
import base64

# ------------------ Session State Setup ------------------
if 'is_authorized' not in st.session_state:
    st.session_state.is_authorized = False
if 'data_store' not in st.session_state:
    st.session_state.data_store = {}
if 'failed_attempts' not in st.session_state:
    st.session_state.failed_attempts = 0
if 'MAX_ATTEMPTS' not in st.session_state:
    st.session_state.MAX_ATTEMPTS = 3

# ------------------ Helper Functions ------------------
def generate_key(passkey: str) -> bytes:
    return base64.urlsafe_b64encode(passkey.ljust(32)[:32].encode())

def encrypt_data(data: str, passkey: str) -> bytes:
    key = generate_key(passkey)
    fernet = Fernet(key)
    return fernet.encrypt(data.encode())

def decrypt_data(token: bytes, passkey: str) -> str:
    key = generate_key(passkey)
    fernet = Fernet(key)
    return fernet.decrypt(token).decode()

# ------------------ Reauthorization Page ------------------
def login_page():
    st.title("🔐 Reauthorization Required")
    username = st.text_input("Username", value="", key="login_user")
    password = st.text_input("Password", type="password", key="login_pass")

    if st.button("Login"):
        if username == "admin" and password == "admin123":
            st.session_state.is_authorized = True
            st.session_state.failed_attempts = 0
            st.success("Logged in successfully.")
        else:
            st.error("Invalid credentials.")

# ------------------ Main App ------------------
def main_app():
    st.title("🔒 Secure In-Memory Data Vault")

    st.sidebar.header("Actions")
    action = st.sidebar.radio("Choose an action", ["Store Data", "Retrieve Data", "Logout"])

    if action == "Store Data":
        data = st.text_area("Enter your data")
        passkey = st.text_input("Set a unique passkey", type="password")

        if st.button("Encrypt & Store"):
            if data and passkey:
                encrypted = encrypt_data(data, passkey)
                st.session_state.data_store[passkey] = encrypted
                st.success("Data stored securely!")
            else:
                st.warning("Please provide both data and passkey.")

    elif action == "Retrieve Data":
        passkey = st.text_input("Enter your passkey", type="password")

        if st.button("Retrieve"):
            if passkey in st.session_state.data_store:
                try:
                    decrypted = decrypt_data(st.session_state.data_store[passkey], passkey)
                    st.success("Decrypted Data:")
                    st.code(decrypted, language="text")
                    st.session_state.failed_attempts = 0  # reset on success
                except InvalidToken:
                    st.session_state.failed_attempts += 1
                    st.error("Invalid passkey.")
            else:
                st.session_state.failed_attempts += 1
                st.error("Passkey not found.")

            if st.session_state.failed_attempts >= st.session_state.MAX_ATTEMPTS:
                st.session_state.is_authorized = False
                st.warning("Too many failed attempts. Reauthorization required.")

    elif action == "Logout":
        st.session_state.is_authorized = False
        st.success("Logged out.")

# ------------------ Entry Point ------------------
def main():
    if not st.session_state.is_authorized:
        login_page()
    else:
        main_app()

if __name__ == "__main__":
    main()
