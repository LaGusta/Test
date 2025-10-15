# -*- coding: utf-8 -*-
"""
Created on Wed Oct 15 11:46:58 2025

@author: p.graupner
"""

import streamlit as st
import pandas as pd
import numpy as np

# --- Titel & Beschreibung ---
st.title("🚀 Meine erste Streamlit App")
st.write("Dies ist eine kleine Test-App, die du direkt auf Streamlit Cloud hosten kannst.")

# --- Eingabe ---
name = st.text_input("Wie heißt du?", "Philipp")
st.write(f"👋 Hallo {name}!")

# --- Interaktive Elemente ---
option = st.selectbox(
    "Wähle eine Lieblingszahl:",
    [3, 7, 13, 42]
)
st.write(f"Du hast die Zahl **{option}** gewählt.")

# --- Datenvisualisierung ---
st.header("📊 Zufallsdaten")
data = pd.DataFrame(
    np.random.randn(10, 3),
    columns=["A", "B", "C"]
)
st.line_chart(data)

# --- Schieberegler ---
zahl = st.slider("Wähle eine Zahl:", 0, 100, 50)
st.write("Deine Zahl plus 10 ist:", zahl + 10)
