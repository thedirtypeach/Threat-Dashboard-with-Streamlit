'''
    # --- Uses --- #

    1.) Create a webpage simply by creating a python (".py") file in the "pages" directory. With the streamlit library, this project's file structure automatically creates pages in the
            web app when you create a ".py" file in the pages directory.

    2.) Given a user-provided URL - and upon pressing either "enter" or clicking on the "Check Threat" button - upload the URL to a virustotal
            url-receiving-endpoint (via POST request), then request an analysis of that URL (via GET request).

        2a.) This is achieved by leveraging python's built-in requests library for making API requests, a free-to-use personal API key from VirusTotal,
                and two user-made functions to isolate the POST requests from the GET requests.
                
        2b.) See # --- Functions --- # for more
'''

import streamlit as st
import os
from dotenv import load_dotenv
import requests
import pandas as pd
import time
import re


# --- Functions --- #

# Function to upload a user-defined URL to the Virustotal "urls" endpoint for analysis.
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
        raise Exception(f"Error submitting URL for scanning. Status code: {response.status_code}, {response.text}")
    
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

    # While loop, used to check for "completed" status.
    while True:

        # Make an API GET request to receive data about the url that was scanned.
        response = requests.get(analysis_url, headers=headers)
        
        # Assign the data being received to the results variable.
        results = response.json()

        # Create the status variable to contain the scan's "status"
        status = results['data']['attributes']['status']

        # Problem: The response from the GET request doesn't always include all attributes
        #   necessary to build the data charts.

        # Solution: Create the attributes_status variable to contain what ends up being
        #   a list of dictionaries. Create the attributes_found variable and initialize it
        #   to false. Run a while loop to iterate through each "key : value" pair to check
        #   for a "value" in any key to be greater than 1. If any "value" is greater than 1
        #   then set attributes_found to True. We use the attributes_found variable for error
        #   handling. If 30 seconds pass by and attributes_found is still not equal to True,
        #   then print out that an error occured.

        # Explanation: This works because all of the "values" in each "key : value" pair are updated
        #   at the same time (I.e. The data is either there - or it's not). So, once any one of
        #   the values are equal to, or greater than 1, we can assume the virustotal analysis
        #   endpoint is finished with its analysis. See code below for implementation.

        # Create the attributes_status variable because this is often left out.
        attributes_status = results['data']['attributes']['stats']

        # Initialize attributes_found to false.
        attributes_found = True

        # Initialize start_time.
        start_time = time.time()
         
        # For loop to iterate through attributes_status to check for a value greater than 1.
        while attributes_found == False and (time.time() - start_time) < 30:
            for key, value in attributes_status.items():
                if value > 1:
                    # Success, leave this loop and continue with code.
                    attributes_found = True
                    break

            if attributes_found != True:
                # Check if 30 seconds have passed.
                if (time.time() - start_time) >= 30:
                    # Failed, 30 seconds have passed and API request not fulfilled.
                    st.error("API Request took too long to respond. Please try again.")  
                else:
                    time.sleep(1)             

        #st.write(attributes_status)
        
        # If the scan's status is equal to "completed" then resume code, otherwise keep trying forever.
        # This is the part of the code where you might want to implement some error handling.
        if status == 'completed' and attributes_found:
            break

        # Add a delay if needed to prevent rapid, continuous requests
        time.sleep(1)

    # Error handling for response.
    if response.ok:
        return response.json()
    else:
        raise Exception(f"Error retrieving analysis results: {response.status_code}, {response.text}")

# Function to check if the user-defined URL is a valid URL.
def is_valid_url(url):
    # Check if the URL starts with http:// or https://, if not, prepend http://
    if not url.startswith(('http://', 'https://')):
        url = 'https://' + url

    # Regular expression for validating a URL
    regex = re.compile(
        r'^(?:http|ftp)s?://' # http:// or https://
        r'(?:(?:[A-Z0-9](?:[A-Z0-9-]{0,61}[A-Z0-9])?\.)+(?:[A-Z]{2,6}\.?|[A-Z0-9-]{2,}\.?)|' # domain...
        r'localhost|' # localhost...
        r'\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}|' # ...or ipv4
        r'\[?[A-F0-9]*:[A-F0-9:]+\]?)' # ...or ipv6
        r'(?::\d+)?' # optional port
        r'(?:/?|[/?]\S+)$', re.IGNORECASE)
    return re.match(regex, url) is not None


# --- Main --- #

# The main function, where some of the magic happens.
def main():

    # Set page configuration, this should be the first thing that occurs.
    st.set_page_config(
        page_title="Scan a URL",
        page_icon="🛰",
        layout="centered",
        initial_sidebar_state="collapsed"
        )

    # Create a button to take you back home.
    if st.button("⬅", help="Back"):
        st.switch_page("1_Home.py")

    # Set the title of the page
    st.title("Scan a URL")

    # Create the search bar to let the user enter a website.
    user_input_url = st.text_input("Search or scan a URL", key="url_input", help="Upload a url to scan it with Virustotal.")

    # Add a note to instruct the user to click the button after entering the URL.
    #st.caption("Please click the 'Check Threat' button after entering the URL.")


    # Initialize the button_pressed session state to false.
    if 'button_pressed' not in st.session_state:
        st.session_state.button_pressed = False

    # Make a streamlit.button labeled, "Check Threat".
    # If the button is pressed, then set the button_pressed state to true.
    if st.button("Check Threat", use_container_width=False):
        st.session_state.button_pressed = True

    # Check for Enter key press to trigger the threat check. Requires user_input_url to not be null.
    if st.session_state.button_pressed and is_valid_url(user_input_url):

        # Use streamlit.spinner to temporarily display a message while executing code below.
        with st.spinner('Uploading URL to VirusTotal...'):

            # Reset enter_pressed and button_pressed status.
            #st.session_state.enter_pressed = False
            st.session_state.button_pressed = False

            # Call the submit_url_for_scanning function and assign the value it returns to the analysis_id variable.
            analysis_id = submit_url_for_scanning(user_input_url)
            time.sleep(2)

        # Use the st.spinner function to change the text next to the spinner to indicate next step.
        with st.spinner('Fetching data from VirusTotal...'):

            # Call the get_scanning_results function and assign the value it returns to results variable.
            results = get_scanning_results(analysis_id)
            time.sleep(1)

            # Store the results in session state as, "last_results".
            st.session_state.last_results = results

        # Display the results, kind of ambiguous because you could use results instead of "st.session_state.last_results" and yield the same results.
        # This should also end up as a function...
        if 'last_results' in st.session_state:

            # Parse data from results
            results_stats = results["data"]["attributes"]["stats"]
            results_all = results["data"]["attributes"]["results"]

            # Create a dataframe for the overall results.
            df_stats = pd.DataFrame(
                {
                    "Malicious": [results_stats["malicious"]],
                    "Suspicious": [results_stats["suspicious"]],
                    "Undetected": [results_stats["undetected"]],
                    "Harmless": [results_stats["harmless"]],
                    "Timeout": [results_stats["timeout"]]
                }
            )

            # Create a dataframe for the rest of the data.
            results_data = []
            for engine, details in results_all.items():
                details["engine_name"] = engine
                results_data.append(details)

            df_all = pd.DataFrame(results_data)

            # Print the overall results dataframe to the screen.
            st.dataframe(
                df_stats,
                use_container_width=True,
                hide_index=True,
            )

            # Print the results from each security system.
            st.dataframe(
                df_all,
                use_container_width=True,
                hide_index=True,
                )

            # The lazy way to print results.
            #st.json(st.session_state.last_results)

            # Reset the button_pressed state after finished.
            st.session_state.button_pressed = False
    
    #
    elif not is_valid_url(user_input_url) and st.session_state.button_pressed:
        
        st.error("Invalid URL. Please enter a valid URL.")
        st.session_state.button_pressed = False



main()

# --- Miscellanious Code --- # 

            # Create a dataframe
            #df = pd.json_normalize(results)
            #st.table(df)

            # Expander
            #with st.expander("See details"):
            #    st.json(results)

            # Use this to write the url that the user is searching for to the host.
            #   st.text(results['meta']['url_info']['url'])

            # For this part you'll probably want to create a combination of columns and containers to help visualize data.
                # This is because streamlit has built-in container and column functions.
                # Additionally, MatPlotLib and Plotly are two libraries commonly leveraged
                # to carry out visual data analyzation.
