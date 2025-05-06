# import streamlit as st
# import hashlib
# from cryptography.fernet import Fernet

# KEY = Fernet.generate_key()
# chiper = Fernet(KEY)

# stored_data = {}
# failed_attempts = 0

# # function to hash passkey
# def has_passkey(passkey):
#     return hashlib.sha256(passkey.encode()).hexdigest()

# # function to encrypt data 
# def encrypt_data(text, passkey):
#     return chiper.encrypt(text.encode()).decode()

# # function to decrypt data 
# def decrypt_data(encrypted_text, passkey):
#     global failed_attempts
#     hashed_passkey = has_passkey(passkey)

#     for key, value in stored_data.items():
#         if value["encrypted_text"] == encrypted_text and value["passkey"] == hashed_passkey:
#             failed_attempts = 0
#             return chiper.decrypt(encrypted_text.encode()).decode()
#     failed_attempts += 1
#     return None

# # Streamlit UI 
# st.title("🔒 Secure Data Encryption System")

# # Navigation
# menu = ["Home", "Store Data", "Retrieve Data", "Login"]
# choice = st.sidebar.selectbox("Navigation", menu)

# if choice == "Home":
#     st.subheader("Welcome to Secure Data System")
#     st.write("Use this app to **securely store and retrieve data** using unique passkeys.")

# elif choice == "Store Data":
#     st.subheader("📂 Store Data Securely")
#     user_data = st.text_area("Enter Data:")
#     passkey = st.text_input("Enter Passkey:", type="password")

#     if st.button("Encrypt & Save"):
#         if user_data and passkey:
#             encrypted_text = encrypt_data(user_data, passkey)
#             hashed_passkey = has_passkey(passkey)
#             stored_data[encrypted_text] = {"encrypted_text": encrypted_text, "passkey": hashed_passkey}
#             st.success("✅ Data stored securely!")
#         else:
#             st.error("⚠️ Both fields are required!")

# elif choice == "Retrieve Data":
#     st.subheader("🔍 Retrieve Your Data")
#     encrypted_text= st.text_area("Enter Encrypted data")
#     passkey = st.text_input("Enter a passkey", type="password")

#     if st.button("Decrypt"):
#         if encrypted_text and passkey:
#             decrypted_text = decrypt_data(encrypted_text, passkey)

#             if decrypted_text:
#                 st.success(f"✅ Decrypted Data: {decrypted_text}")
#             else:
#                 st.error(f"❌ Incorrect passkey! Attempts remaining: {3 - failed_attempts}")

#                 if failed_attempts >= 3:
#                     st.warning("🔒 Too many failed attempts! Redirecting to Login Page.")
#                     st.experimental_rerun()

#         else:
#             st.write("Both Fields are required")

# elif choice == "Login":
#     st.subheader("🔑 Reauthorization Required")
#     login_pass = st.text_input("Enter Master Password:", type="password")

#     if st.button("Login"):
#         if login_pass == "admin123":  # Hardcoded for demo, replace with proper auth
#             # global failed_attempts
#             failed_attempts = 0
#             st.success("✅ Reauthorized successfully! Redirecting to Retrieve Data...")
#             st.experimental_rerun()
#         else:
#             st.error("❌ Incorrect password!")













import streamlit as st
import hashlib
import base64
from cryptography.fernet import Fernet

# --- Helper Functions ---

def has_passkey(passkey):
    return hashlib.sha256(passkey.encode()).hexdigest()

def get_fernet(passkey):
    key = hashlib.sha256(passkey.encode()).digest()  # 32-byte key
    return Fernet(base64.urlsafe_b64encode(key))     # base64 encoded

def encrypt_data(text, passkey):
    fernet = get_fernet(passkey)
    return fernet.encrypt(text.encode()).decode()

def decrypt_data(encrypted_text, passkey):
    hashed_passkey = has_passkey(passkey)
    for key, value in st.session_state.stored_data.items():
        if value["encrypted_text"] == encrypted_text and value["passkey"] == hashed_passkey:
            try:
                fernet = get_fernet(passkey)
                st.session_state.failed_attempts = 0
                return fernet.decrypt(encrypted_text.encode()).decode()
            except:
                return None  # invalid decryption
    st.session_state.failed_attempts += 1
    return None

# --- Session Initialization ---

if "stored_data" not in st.session_state:
    st.session_state.stored_data = {}
if "failed_attempts" not in st.session_state:
    st.session_state.failed_attempts = 0
if "page" not in st.session_state:
    st.session_state.page = "Home"

# --- UI ---

st.title("🔒 Secure Data Encryption System")

menu = ["Home", "Store Data", "Retrieve Data", "Login"]
choice = st.sidebar.selectbox("Navigation", menu, index=menu.index(st.session_state.page))
st.session_state.page = choice

# --- Pages ---

if choice == "Home":
    st.subheader("Welcome to Secure Data System")
    st.write("Use this app to **securely store and retrieve data** using unique passkeys.")

elif choice == "Store Data":
    st.subheader("📂 Store Data Securely")
    user_data = st.text_area("Enter Data:")
    passkey = st.text_input("Enter Passkey:", type="password")

    if st.button("Encrypt & Save"):
        if user_data and passkey:
            encrypted_text = encrypt_data(user_data, passkey)
            hashed_passkey = has_passkey(passkey)
            st.session_state.stored_data[encrypted_text] = {
                "encrypted_text": encrypted_text,
                "passkey": hashed_passkey
            }
            st.success("✅ Data stored securely!")
            st.code(encrypted_text, language="text")
        else:
            st.error("⚠️ Both fields are required!")

elif choice == "Retrieve Data":
    st.subheader("🔍 Retrieve Your Data")
    encrypted_text = st.text_area("Enter Encrypted Data")
    passkey = st.text_input("Enter Passkey", type="password")

    if st.button("Decrypt"):
        if encrypted_text and passkey:
            decrypted_text = decrypt_data(encrypted_text, passkey)

            if decrypted_text:
                st.success("✅ Decrypted Data:")
                st.code(decrypted_text, language="text")
            else:
                st.error(f"❌ Incorrect passkey! Attempts remaining: {3 - st.session_state.failed_attempts}")
                if st.session_state.failed_attempts >= 3:
                    st.warning("🔒 Too many failed attempts! Redirecting to Login Page.")
                    st.session_state.failed_attempts = 0  # reset
                    st.session_state.page = "Login"
                    st.rerun()
        else:
            st.error("⚠️ Both fields are required!")

elif choice == "Login":
    st.subheader("🔑 Reauthorization Required")
    login_pass = st.text_input("Enter Master Password:", type="password")

    if st.button("Login"):
        if login_pass == "admin123":
            st.session_state.failed_attempts = 0
            st.success("✅ Reauthorized successfully! Redirecting to Retrieve Data...")
            st.session_state.page = "Retrieve Data"
            st.rerun()
        else:
            st.error("❌ Incorrect password!")
