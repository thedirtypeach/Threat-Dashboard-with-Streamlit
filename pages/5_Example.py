import streamlit as st
import random

# Set page configuration, this should be the first thing that occurs.
st.set_page_config(
    page_title="Moonlit Shop",
    page_icon="📂",
    initial_sidebar_state="collapsed",
    layout="wide"
    )

col1, col2, col3 = st.columns([1, 1, 1])

#col2.title("Moonlit Shop")
col2.markdown("<h1 style='text-align: center; color: white;'>Moonlit Shop</h1>", unsafe_allow_html=True)

columns = col1, col2, col3, col4, col5, col6, col7 = st.columns([1, 2, 2, 2, 2, 2, 1])

for column in columns:
    if column != col1 and column != col7:
        with column.container():
            st.image('Icons/a mug.jpg', caption='wow look at that mug!', output_format="auto")
            #st.button("Buy now!")

if col2.button("Buy now!", key="mug1", use_container_width=True):
    col2.write("Now make the API request and load transaction.")
    col2.write("Then redirect the user to Paypal.")
    col2.write("Also probably check the 'cart' status")

col3.button("Buy now!", key="mug2", use_container_width=True)
