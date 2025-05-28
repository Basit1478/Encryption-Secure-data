# 🔐 Streamlit Secure Data Vault

A lightweight in-memory secure data storage and retrieval system built with Streamlit.

## 🚀 Features

- Store encrypted data with a unique passkey.
- Decrypt data only by providing the correct passkey.
- Automatically locks out users after multiple failed attempts.
- Reauthorization/login page to regain access.
- 100% in-memory operation — no external database.

## 🛡️ Default Login

| Username | Password   |
|----------|------------|
| admin    | admin123   |

> You can modify credentials in `app.py` as needed.

---

## 🧪 Setup Instructions

### 1. Clone the Repo
```bash
git clone https://github.com/basit1478/Encryption_secure_data_app.git
cd Encryption_secure_data_app
```

### 2. Install Dependencies
```bash
pip install -r requirements.txt
```

### 3. Run the App
```bash
streamlit run app.py
```

