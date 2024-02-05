import streamlit as st
import os
from dotenv import load_dotenv
import requests
import pandas as pd


# ----- Functions ----- #

# Function to upload a user-defined URL to a Virustotal endpoint to be analyzed.
# Returns the "analysis_id" to be used in the get_scanning_results() function.
def submit_url_for_scanning(url):

    # Specify the API endpoint to be used for URL scanning.
    virustotal_url = f"https://www.virustotal.com/api/v3/urls"

    # Load the .env file from the environment (the Operating System).
    load_dotenv()
    api_key = os.getenv('VIRUSTOTAL_API_KEY')

    # Initialize the headers list.
    headers = {
        "accept": "application/json",
        "content-type": "application/x-www-form-urlencoded",
        "x-apikey": api_key
    }

    # Create payload as mentioned in the Virustotal API reference.
    payload = {"url": url}

    # Make an API POST Request to *upload* user-defined URL to the Virustotal URL scanning endpoint.
    response = requests.post(virustotal_url, headers=headers, data=payload)

    # Error handling for response.
    if response.ok:
        result = response.json()
        analysis_id = result['data']['id']
        return analysis_id
    else:
        raise Exception(f"Error submitting URL for scanning: {response.status_code}, {response.text}")
    
# Function to retrieve the analysis of a previously uploaded url.
# Returns the analysis of the specified url in the json format.
def get_scanning_results(analysis_id):
    
    # Load the .env file from the environment (the Operating System).
    load_dotenv()
    api_key = os.getenv('VIRUSTOTAL_API_KEY')


    # Request scan information on the user-specified analysis_id.
    analysis_url = f"https://www.virustotal.com/api/v3/analyses/{analysis_id}"
    
    # Initialize the headers variable.
    headers = {"accept": "application/json",
               "x-apikey": api_key}

    # Make an API GET request to request data about the url that was scanned.
    response = requests.get(analysis_url, headers=headers)

    # Error handling for response.
    if response.ok:
        return response.json()
    else:
        raise Exception(f"Error retrieving analysis results: {response.status_code}, {response.text}")


# ----- Main ----- #

# The main function, where some of the magic happens.
def main():

    # Set page configuration, this should be the first thing that occurs.
    st.set_page_config(
        page_title="Threat Intelligence Dashboard",
        page_icon="radar",
        )

    # Create a button to take you home.
    if st.button("Home"):
        st.switch_page("1_Home.py")

    # Set the title of the "Scan a URL" page
    st.title("Scan a URL")

    # Create the search bar to let the user enter a website.
    user_input_url = st.text_input("Enter URL/Domain/IP/File hash")

    # Make a boolean variable "button_pressed" and a streamlit.button.
    # If the button is pressed, then "button_pressed" value becomes true.
    button_pressed = st.button("Check Threat")

    # Check for Enter key press to trigger the threat check
    if user_input_url and (st.session_state.enter_pressed or button_pressed):

        # Reset enter_pressed status.
        st.session_state.enter_pressed = False

        # Using streamlit.spinner to call the functions that do all the work.
        with st.spinner('Fetching data from VirusTotal...'):
            analysis_id = submit_url_for_scanning(user_input_url)
            results = get_scanning_results(analysis_id)
            #st.json(results)

            # Create a dataframe
            df = pd.json_normalize(results)
            st.table(df)

            # Expander
            with st.expander("See details"):
                st.json(results)

    else:
        st.session_state.enter_pressed = True  # Set enter_pressed when Enter key is pressed

main()