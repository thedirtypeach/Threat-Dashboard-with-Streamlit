import streamlit as st

# This has to be the first thing in the main function. Don't move it.
# Basic page configuration stuff.
st.set_page_config(
    page_title="Threat Intelligence Dashboard",
    page_icon="",
    )

# Create the title of the Threat Dashboard.
st.title("Threat Dashboard")

with st.container(height=200):
    st.text("Eventually, this area will contain a neat dashboard comprised of commonly visited websites.")