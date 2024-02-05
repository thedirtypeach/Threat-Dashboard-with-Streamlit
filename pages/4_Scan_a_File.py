import streamlit as st

# Set page configuration, this should be the first thing that occurs.
st.set_page_config(
    page_title="Threat Intelligence Dashboard",
    page_icon="radar",
    )

# Set the title of the "Scan a URL" page
st.title("Scan a File")

# Create the search bar to let the user enter a website.
resource = st.text_input("Enter URL/Domain/IP/File hash")

#if st.button("Check Threat"):
#    with st.spinner('Fetching data from VirusTotal...'):
#        threat_data = funk.query_virustotal(resource)
#        funk.display_threat_info(threat_data)
# Function to change the page

# Set page configuration, this should be the first thing that occurs.
st.set_page_config(
    page_title="Threat Intelligence Dashboard",
    page_icon="radar",
    )

# Set the title of the "Scan a URL" page
st.title("Scan a File")

# Create the search bar to let the user enter a website.
resource = st.text_input("Enter URL/Domain/IP/File hash")

#if st.button("Check Threat"):
#    with st.spinner('Fetching data from VirusTotal...'):
#        threat_data = funk.query_virustotal(resource)
#        funk.display_threat_info(threat_data)
# Function to change the page