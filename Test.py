import time
from datetime import datetime, timedelta

import pyotp
import qrcode
import streamlit as st
import streamlit_authenticator as stauth
from io import BytesIO

st.set_page_config(page_title="Bilton Login", page_icon="🔐", layout="centered")

# ---------------------------
# 1) Konfiguration laden
# ---------------------------
AUTH = st.secrets["auth_config"]
CREDS = st.secrets["credentials"]["usernames"]
TOTP_SECRETS = st.secrets.get("totp", {})
APP_META = st.secrets.get("app_meta", {})
ISSUER = APP_META.get("issuer", "Streamlit App")
APP_LABEL = APP_META.get("app_label", "Login")

# streamlit-authenticator erwartet ein verschachteltes Dict:
credentials = {"usernames": {}}
for uname, data in CREDS.items():
    # streamlit-authenticator möchte {password: <hash>, email:..., name:...}
    credentials["usernames"][uname] = {
        "name": data.get("name", uname),
        "email": data.get("email", ""),
        "password": data["password"],
    }

# Authenticator-Objekt (setzt auch Cookie)
authenticator = stauth.Authenticate(
    credentials=credentials,
    cookie_name=AUTH["cookie_name"],
    key=AUTH["cookie_key"],
    cookie_expiry_days=AUTH.get("cookie_expiry_days", 1),
)

# ---------------------------
# 2) Login-Formular
# ---------------------------
st.title("🔐 Bilton – Geschützter Zugang")

authenticator.login(location="main", key="Login")

auth_status = st.session_state.get("authentication_status")
username    = st.session_state.get("username")
name        = st.session_state.get("name")

if auth_status is False:
    st.error("Falsche Zugangsdaten.")
    st.stop()
elif auth_status is None:
    st.info("Bitte Benutzername & Passwort eingeben.")
    st.stop()

# E-Mail aus deinen Credentials (oder eigener Benutzerquelle)
user_email = st.secrets["credentials"]["usernames"][username]["email"]

# 2. Faktor per E-Mail-OTP
if "otp_ok" not in st.session_state or not st.session_state["otp_ok"]:
    email_otp_step(username, user_email)
    st.stop()

# Ab hier: vollständig eingeloggt
st.success(f"Eingeloggt als {name} ({username})")

# Wenn wir hier sind: Passwort ok → nun 2FA erfordern
# ---------------------------------------------------
# Session-Init
if "expires_at" not in st.session_state:
    st.session_state.expires_at = None
if "role" not in st.session_state:
    st.session_state.role = CREDS[username].get("role", "user")

# ---------------------------
# 3) Session-Timeout prüfen
# ---------------------------
def touch_session(timeout_minutes: int):
    # Sliding expiration: bei Aktivität neu setzen
    st.session_state.expires_at = datetime.utcnow() + timedelta(minutes=timeout_minutes)

def check_timeout():
    if st.session_state.expires_at is None:
        return
    if datetime.utcnow() > st.session_state.expires_at:
        # Abgelaufen → Logout + Info
        st.warning("Session abgelaufen. Bitte erneut anmelden.")
        authenticator.logout("Neu anmelden", "main")
        st.stop()

# Beim erstmaligen Eintritt nach Passwort-Anmeldung Timeout setzen
if st.session_state.expires_at is None:
    touch_session(AUTH.get("timeout_minutes", 20))

# Bei jedem Run Timeout validieren (Idle-Kontrolle)
check_timeout()

# ---------------------------
# 4) TOTP-2FA
# ---------------------------
import smtplib, ssl, secrets, string, time
from email.message import EmailMessage
from datetime import datetime, timedelta

import streamlit as st
from passlib.hash import bcrypt

# --- OTP-Store: für Tests in Session; für Produktion: DB (Supabase/Postgres) ---
def _otp_store_key(username): return f"otp_{username}"
def create_and_store_otp(username, ttl_seconds=300):
    code = "".join(secrets.choice(string.digits) for _ in range(6))
    # Nur Hash speichern, nicht den Klartext-Code
    entry = {
        "hash": bcrypt.hash(code),
        "expires_at": datetime.utcnow() + timedelta(seconds=ttl_seconds),
        "attempts": 0,
        "last_sent": datetime.utcnow(),
    }
    st.session_state[_otp_store_key(username)] = entry
    return code

def verify_otp(username, code, max_attempts=5):
    entry = st.session_state.get(_otp_store_key(username))
    if not entry:
        return False, "Kein Code angefordert."
    if datetime.utcnow() > entry["expires_at"]:
        return False, "Code abgelaufen."
    if entry["attempts"] >= max_attempts:
        return False, "Zu viele Fehlversuche. Bitte neuen Code anfordern."
    entry["attempts"] += 1
    ok = bcrypt.verify(code, entry["hash"])
    if ok:
        # Einmal verwendbar
        st.session_state.pop(_otp_store_key(username), None)
        return True, None
    return False, "Code ungültig."

def can_resend(username, cooldown_seconds=30):
    entry = st.session_state.get(_otp_store_key(username))
    if not entry: return True
    return (datetime.utcnow() - entry["last_sent"]).total_seconds() >= cooldown_seconds

def mark_resent(username):
    entry = st.session_state.get(_otp_store_key(username))
    if entry:
        entry["last_sent"] = datetime.utcnow()

# --- E-Mail Versand ---
def send_email_code(to_addr: str, code: str):
    cfg = st.secrets["email"]
    msg = EmailMessage()
    msg["Subject"] = cfg.get("subject", "Dein Anmeldecode")
    msg["From"] = cfg["from_addr"]
    msg["To"] = to_addr
    msg.set_content(
        f"""Hallo,

dein Einmalcode lautet: {code}

Er ist 5 Minuten gültig. Wenn du die Anmeldung nicht gestartet hast, ignoriere diese E-Mail.

– Bilton App
"""
    )
    context = ssl.create_default_context()
    with smtplib.SMTP(cfg["host"], cfg.get("port", 587)) as server:
        if cfg.get("use_tls", True):
            server.starttls(context=context)
        server.login(cfg["user"], cfg["password"])
        server.send_message(msg)

# --- Nach Passwort-Login: E-Mail-OTP Schritt ---
def email_otp_step(username, email_address):
    st.subheader("Zweiter Schritt: E-Mail-Code")
    # Code erzeugen & senden (nur wenn noch keiner existiert)
    if _otp_store_key(username) not in st.session_state:
        code = create_and_store_otp(username, ttl_seconds=300)
        try:
            send_email_code(email_address, code)
            st.success(f"Ein Code wurde an {email_address} gesendet (gültig 5 Minuten).")
        except Exception as e:
            st.error("Fehler beim Versand des Codes. Bitte später erneut versuchen.")
            st.stop()

    # Formular für Codeeingabe
    with st.form("otp_form"):
        otp = st.text_input("6-stelligen Code eingeben", max_chars=6)
        submitted = st.form_submit_button("Bestätigen")
    if submitted:
        ok, err = verify_otp(username, otp)
        if ok:
            st.session_state["otp_ok"] = True
            st.success("Verifizierung erfolgreich.")
            st.rerun()
        else:
            st.error(err)

    # Resend mit Cooldown
    if st.button("Code erneut senden"):
        if can_resend(username, cooldown_seconds=30):
            code = create_and_store_otp(username, ttl_seconds=300)
            try:
                send_email_code(email_address, code)
                mark_resent(username)
                st.info("Neuer Code wurde gesendet.")
            except Exception:
                st.error("Versand fehlgeschlagen.")
        else:
            st.warning("Bitte warte kurz, bevor du erneut sendest.")


# Ab hier: Benutzer ist vollständig eingeloggt (PW + TOTP)
# --------------------------------------------------------
touch_session(AUTH.get("timeout_minutes", 20))  # Aktivität → Timeout verlängern
st.success(f"Willkommen {name} · Rolle: **{st.session_state.role}**")

st.info("Dies ist ein Demo-Screen. Hänge hier später deine App-Inhalte an.")

# Rollenbeispiel
role = st.session_state.role
if role == "admin":
    st.write("🛡️ Admin-Panel (Demo): Hier könnten Admin-Funktionen erscheinen.")
elif role == "viewer":
    st.write("👀 Viewer-Ansicht (Demo).")

# Komfort: Logout-Button in der Sidebar
authenticator.logout("Abmelden", "sidebar")



