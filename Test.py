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

name, auth_status, username = authenticator.login("Anmeldung", "main")

if auth_status is False:
    st.error("Falsche Zugangsdaten.")
    st.stop()
elif auth_status is None:
    st.info("Bitte Benutzername & Passwort eingeben.")
    st.stop()

# Wenn wir hier sind: Passwort ok → nun 2FA erfordern
# ---------------------------------------------------
# Session-Init
if "totp_ok" not in st.session_state:
    st.session_state.totp_ok = False
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
def build_otpauth_uri(secret: str, user: str) -> str:
    # otpauth://totp/<Issuer>:<User>?secret=<SECRET>&issuer=<Issuer>&digits=6&period=30
    # Achtung: spaces/sonderzeichen vermeiden – streamlit zeigt Label separat
    issuer_clean = ISSUER.replace(" ", "%20")
    label_clean = f"{APP_LABEL}-{user}".replace(" ", "%20")
    return f"otpauth://totp/{issuer_clean}:{label_clean}?secret={secret}&issuer={issuer_clean}&digits=6&period=30"

def qr_image_from_uri(uri: str):
    img = qrcode.make(uri)
    buf = BytesIO()
    img.save(buf, format="PNG")
    buf.seek(0)
    return buf

user_totp_secret = TOTP_SECRETS.get(username)

st.divider()
st.subheader("Zwei-Faktor-Authentifizierung (TOTP)")

# Setup-Hinweis/QR nur anzeigen, wenn ein Secret existiert (wir verwalten es zentral)
if user_totp_secret:
    with st.expander("TOTP einrichten / QR-Code anzeigen"):
        st.write("Scanne diesen QR-Code mit deiner Authenticator-App (Google/Microsoft Authenticator o.ä.).")
        uri = build_otpauth_uri(user_totp_secret, username)
        st.image(qr_image_from_uri(uri), caption="Authenticator-QR", use_column_width=False)
        st.code(uri, language="text")
else:
    st.error("Für diesen Benutzer ist kein TOTP-Secret hinterlegt. Bitte wende dich an den Admin.")
    authenticator.logout("Abmelden", "sidebar")
    st.stop()

if not st.session_state.totp_ok:
    with st.form("totp_form"):
        code = st.text_input("6-stelliger Code", max_chars=6)
        ok = st.form_submit_button("Bestätigen")
    if ok:
        totp = pyotp.TOTP(user_totp_secret)
        # valid_window=1 erlaubt +/- 30s Toleranz
        if code and totp.verify(code, valid_window=1):
            st.session_state.totp_ok = True
            touch_session(AUTH.get("timeout_minutes", 20))  # bei Erfolg Session verlängern
            st.success("2-Faktor verifiziert.")
            time.sleep(0.5)
            st.experimental_rerun()
        else:
            st.error("Ungültiger TOTP-Code.")
            st.stop()

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
