import streamlit as st

st.title("FAQ")
st.text("q.) How do I get to the home page?")

st.text("a.) click below")

if st.button("home"):
    st.switch_page("1_Home.py")