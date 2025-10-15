import smtplib
import ssl
import secrets
import string
import time
from email.message import EmailMessage
from datetime import datetime, timedelta, timezone

import streamlit as st
import streamlit_authenticator as stauth
from passlib.hash import bcrypt

# ---------------------------------------------------------
# Grundkonfiguration
# ---------------------------------------------------------
st.set_page_config(page_title="Bilton Login (E-Mail-OTP)", page_icon="🔐", layout="centered")

AUTH = st.secrets["auth_config"]
CREDS = st.secrets["credentials"]["usernames"]

# streamlit-authenticator erwartet dieses Schema:
credentials = {"usernames": {}}
for uname, data in CREDS.items():
    credentials["usernames"][uname] = {
        "name": data.get("name", uname),
        "email": data.get("email", ""),
        "password": data["password"],  # bcrypt hash
    }

authenticator = stauth.Authenticate(
    credentials=credentials,
    cookie_name=AUTH["cookie_name"],
    key=AUTH["cookie_key"],
    cookie_expiry_days=AUTH.get("cookie_expiry_days", 1),
)

# ---------------------------------------------------------
# Hilfsfunktionen: Session-Timeout (Sliding)
# ---------------------------------------------------------
def _touch_session():
    st.session_state["expires_at"] = datetime.now(timezone.utc) + timedelta(
        minutes=AUTH.get("timeout_minutes", 20)
    )

def _check_timeout():
    exp = st.session_state.get("expires_at")
    if not exp:
        return
    if datetime.now(timezone.utc) > exp:
        st.warning("Session abgelaufen. Bitte erneut anmelden.")
        authenticator.logout("Neu anmelden", "main")
        st.stop()

# ---------------------------------------------------------
# Hilfsfunktionen: E-Mail-OTP
# ---------------------------------------------------------
def _otp_store_key(username: str) -> str:
    # Session-Key je Benutzer (nur Hash & Metadaten, kein Klartext)
    return f"otp_{username}"

def create_and_store_otp(username: str, ttl_seconds: int = 300) -> str:
    """Erzeuge 6-stelligen Code, speichere nur den Hash + Ablauf im Session-State und gib den Klartext zurück (für Versand)."""
    code = "".join(secrets.choice(string.digits) for _ in range(6))
    entry = {
        "hash": bcrypt.hash(code),
        "expires_at": (datetime.now(timezone.utc) + timedelta(seconds=ttl_seconds)).isoformat(),
        "attempts": 0,
        "last_sent": datetime.now(timezone.utc).isoformat(),
    }
    st.session_state[_otp_store_key(username)] = entry
    return code

def _entry_for(username: str):
    return st.session_state.get(_otp_store_key(username))

def verify_otp(username: str, code: str, max_attempts: int = 5):
    entry = _entry_for(username)
    if not entry:
        return False, "Kein Code angefordert."
    # Ablauf prüfen
    if datetime.now(timezone.utc) > datetime.fromisoformat(entry["expires_at"]):
        return False, "Code abgelaufen."
    # Versuche limitieren
    if entry["attempts"] >= max_attempts:
        return False, "Zu viele Fehlversuche. Bitte neuen Code anfordern."
    entry["attempts"] += 1
    ok = bcrypt.verify(code, entry["hash"])
    if ok:
        # Einmalige Verwendung: Eintrag entfernen
        st.session_state.pop(_otp_store_key(username), None)
        return True, None
    return False, "Code ungültig."

def can_resend(username: str, cooldown_seconds: int = 30) -> bool:
    entry = _entry_for(username)
    if not entry:
        return True
    last = datetime.fromisoformat(entry["last_sent"])
    return (datetime.now(timezone.utc) - last).total_seconds() >= cooldown_seconds

def mark_resent(username: str):
    entry = _entry_for(username)
    if entry:
        entry["last_sent"] = datetime.now(timezone.utc).isoformat()

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

def email_otp_step(username: str, email_address: str):
    """UI für den 2. Faktor: E-Mail-OTP senden + verifizieren."""
    st.subheader("Zweiter Schritt: E-Mail-Code")

    # Initial senden (falls noch kein OTP existiert)
    if _otp_store_key(username) not in st.session_state:
        code = create_and_store_otp(username, ttl_seconds=300)  # 5 Minuten
        try:
            send_email_code(email_address, code)
            st.success(f"Ein Code wurde an {email_address} gesendet (gültig 5 Minuten).")
        except Exception:
            st.error("Fehler beim Versand des Codes. Bitte später erneut versuchen.")
            st.stop()

    # Eingabeformular
    with st.form("otp_form"):
        otp = st.text_input("6-stelligen Code eingeben", max_chars=6)
        submitted = st.form_submit_button("Bestätigen")
    if submitted:
        ok, err = verify_otp(username, otp)
        if ok:
            st.session_state["otp_ok"] = True
            _touch_session()  # Aktivität -> Timeout verlängern
            st.success("Verifizierung erfolgreich.")
            time.sleep(0.3)
            st.rerun()
        else:
            st.error(err)

    # Erneut senden (Cooldown)
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

# ---------------------------------------------------------
# UI: Login
# ---------------------------------------------------------
st.title("🔐 Bilton – Geschützter Zugang (E-Mail-OTP)")

# Neuer API-Stil (liefert nichts zurück; Status in session_state)
authenticator.login(location="main", key="Login")

auth_status = st.session_state.get("authentication_status")
username    = st.session_state.get("username")
name        = st.session_state.get("name")

if auth_status is False:
    st.error("Falsche Zugangsdaten.")
    st.stop()
elif auth_status is None:
    st.info("Bitte anmelden.")
    st.stop()

# Passwort korrekt -> Session/Timeout initialisieren
if "expires_at" not in st.session_state:
    _touch_session()
_check_timeout()

# Zweiter Faktor via E-Mail
if not st.session_state.get("otp_ok"):
    # E-Mail des Users aus den Secrets (oder deiner Benutzerquelle)
    user_email = CREDS[username]["email"]
    email_otp_step(username, user_email)
    st.stop()

# ---------------------------------------------------------
# Vollständig eingeloggt ab hier
# ---------------------------------------------------------
# Aktivität verlängert Timeout
_touch_session()

role = CREDS[username].get("role", "user")
st.success(f"Eingeloggt als {name} — Rolle: **{role}**")

st.info("Dies ist ein Demo-Screen. Hänge hier später deine App-Inhalte an.")

if role == "admin":
    st.write("🛡️ Admin-Panel (Demo): Hier könnten Admin-Funktionen erscheinen.")
elif role == "viewer":
    st.write("👀 Viewer-Ansicht (Demo).")

# Komfort: Logout
authenticator.logout("Abmelden", "sidebar")






