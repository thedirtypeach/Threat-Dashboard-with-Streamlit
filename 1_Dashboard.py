'''
Create a dashboard that displays real-time threat intelligence data from VirusTotal.
This could include information on the latest malware, URLs, IPs, and file hashes flagged as malicious.
Users can interact with the dashboard to explore detailed reports or historical trends.
'''

# Import libraries necessary to carry out streamlit functions and capabilities.
import streamlit as st
import pandas as pd # Library for data manipulation
import plotly.express as px
import requests # For handling API requests.
import json # To handle json files.
from dotenv import load_dotenv # To grab your VirusTotal API key.
import os # To access local file system.

# This function queries Virus Total.
def query_virustotal(resource):
    
    # Load the .env variable
    load_dotenv()

    # Assign API_KEY the Virus Total API Key value.
    API_KEY = os.getenv('VIRUSTOTAL_API_KEY')

    # Specify the Virus Total Endpoint
    url = f"https://www.virustotal.com/vtapi/v2/url/report"
    params = {'apikey': API_KEY, 'resource': resource}
    response = requests.get(url, params=params)
    return response.json()

# This function displays threat info.
def display_threat_info(threat_data):
    if threat_data.get('positives', 0) > 0:
        st.write("Threat Found!")
        st.json(threat_data)
    else:
        st.write("No threat detected.")

def load_custom_css():
    st.markdown("""
        <style>
        .stButton > button {
            font-size: 20px;        /* Larger font size */
            height: 3em;            /* Button height */
            width: 100%;            /* Button width, 100% of the container */
            padding: 0.5em 1em;     /* Top-Bottom, Left-Right padding */
            margin: 5px;            /* Margin around the button */
        }
        </style>
        """, unsafe_allow_html=True)

# This function helps visualize threat data.
def visualize_data(data):
    scans = data['scans']
    df = pd.DataFrame.from_dict(scans, orient='index')

    # Bar Chart
    detection_counts = df['detected'].value_counts()
    bar_fig = px.bar(detection_counts, x=detection_counts.index, y=detection_counts.values, 
                     labels={'x':'Detected', 'y':'Count'}, title='Detection Overview')
    st.plotly_chart(bar_fig)

    # Pie Chart
    pie_fig = px.pie(df, names='detected', title='Detection Ratio')
    st.plotly_chart(pie_fig)

# The main function, where all the magic happens.
def main():
    
    # This has to be the first thing in the main function.
    st.set_page_config(
        page_title="Threat Intelligence Dashboard",
        page_icon="Meep",        
        )

    # Apply custom CSS
    load_custom_css()

    # Create the title of the page.
    st.title("Dashboard")
    st.sidebar.success("Select a page above.")

    resource = st.text_input("Enter URL/Domain/IP/File hash")

    if st.button("Check Threat"):
        with st.spinner('Fetching data from VirusTotal...'):
            threat_data = query_virustotal(resource)
            display_threat_info(threat_data)


    # Create a 3x3 grid of buttons
    # First row
    col1, col2, col3 = st.columns(3)
    with col1:
        if st.button('Scan a URL'):
            st.write('Button 1 clicked')
    with col2:
        if st.button('Button 2'):
            st.write('Button 2 clicked')
    with col3:
        if st.button('Button 3'):
            st.write('Button 3 clicked')

    # Second row
    col4, col5, col6 = st.columns(3)
    with col4:
        if st.button('Button 4'):
            st.write('Button 4 clicked')
    with col5:
        if st.button('Button 5'):
            st.write('Button 5 clicked')
    with col6:
        if st.button('Button 6'):
            st.write('Button 6 clicked')

    # Third row
    col7, col8, col9 = st.columns(3)
    with col7:
        if st.button('Button 7'):
            st.write('Button 7 clicked')
    with col8:
        if st.button('Button 8'):
            st.write('Button 8 clicked')
    with col9:
        if st.button('Button 9'):
            st.write('Button 9 clicked')





if __name__ == "__main__":
    main()

    