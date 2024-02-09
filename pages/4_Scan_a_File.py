import streamlit as st


def main():
    # Set page configuration, this should be the first thing that occurs.
    st.set_page_config(
        page_title="Scan a File",
        page_icon="📂",
        initial_sidebar_state="collapsed"
        )

    # Create a button to take you back home.
    if st.button("⬅"):
        st.switch_page("1_Home.py")

    # Set the title of the "Scan a URL" page
    st.title("Scan a File")

    # Create the search bar to let the user enter a website.
    user_input_file = st.file_uploader("Upload a file to begin.", help="Upload a file to scan it with Virustotal.")

    st.write(user_input_file)

    #if st.button("Check Threat"):
    #    with st.spinner('Fetching data from VirusTotal...'):
    #        threat_data = funk.query_virustotal(resource)
    #        funk.display_threat_info(threat_data)
    # Function to change the page

main()