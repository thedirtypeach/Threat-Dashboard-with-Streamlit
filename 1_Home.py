'''
Create a dashboard that displays real-time threat intelligence data from VirusTotal.
This could include information on the latest malware, URLs, IPs, and file hashes flagged as malicious.
Users can interact with the dashboard to explore detailed reports or historical trends.
'''

import streamlit as st # Library for using Streamlit
import plotly.express as px # Library for plotting, which isn't being used because the function is never called in the main()
import pandas as pd # Library for data manipulation
import requests # For handling API requests.
import json # To handle json files.
from dotenv import load_dotenv # To grab your VirusTotal API key.
import os # To access local file system.

# Function to make all buttons look bigger by leveraging CSS***
def load_custom_css():
    st.markdown("""
        <style>
        .stButton > button {
            font-size: 24px;        /* Larger font size */
            height: 5em;            /* Button height */
            width: 100%;            /* Button width, 100% of the container */
            padding: 1em 1.5em;     /* Top-Bottom, Left-Right padding */
            margin: 10px;            /* Margin around the button */
        }
        </style>
        """, unsafe_allow_html=True)

# The main function, where all the magic happens.
def main():
    
    # This has to be the first thing in the main function. Don't move it.
    # Basic page configuration stuff.
    st.set_page_config(
        page_title="Threat Menu",
        page_icon="",
        )

    # Apply custom CSS
    load_custom_css()

    # Create the title of the Threat Dashboard.
    st.title("Threat Menu")
    st.sidebar.success("Select a page above.")

    # Create a 3x1 grid of buttons
    col1, col2, col3 = st.columns(3)
    with col1:
        if st.button(f'Scan a URL'):
            st.switch_page("pages/3_Scan_a_URL.py")            
    with col2:
        if st.button(f'Scan a File'):
            st.switch_page("pages/4_Scan_a_File.py")
    with col3:
        if st.button(f'Scan a File Hash'):
            st.write("button 3")


if __name__ == "__main__":
    main()

    