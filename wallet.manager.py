import streamlit as st
import base58
import json
import requests
from solders.keypair import Keypair  # For Solana keypair generation
from solders.pubkey import Pubkey  # For Solana address validation
from solders.system_program import TransferParams, transfer
from solders.transaction import Transaction

# Solana RPC endpoint
SOLANA_RPC_URL = "https://api.mainnet-beta.solana.com"

# Mock database to store user progress (for demonstration purposes)
USER_DATABASE = {}

def generate_solana_keypair():
    """
    Generates a Solana-compatible keypair using the `solders` library.
    """
    keypair = Keypair()  # Generates a new Solana keypair
    return {
        'address': str(keypair.pubkey()),  # Solana address
        'private_key': base58.b58encode(bytes(keypair)).decode()  # Private key in Base58
    }

def get_solana_balance(address):
    """
    Fetches the SOL balance of a given Solana address using the Solana RPC API.
    """
    payload = {
        "jsonrpc": "2.0",
        "id": 1,
        "method": "getBalance",
        "params": [address]
    }
    response = requests.post(SOLANA_RPC_URL, json=payload)
    if response.status_code == 200:
        data = response.json()
        if 'result' in data:
            balance = data['result']['value'] / 1e9  # Convert lamports to SOL
            return balance
    return None

def validate_solana_address(address):
    """
    Validates a Solana wallet address.
    """
    try:
        Pubkey.from_string(address)  # Use Solders library to validate
        return True
    except:
        return False

def get_user_tokens(wallet_address):
    """
    Fetches the tokens held by the user's wallet (SOL and SPL tokens).
    """
    # Fetch SOL balance
    sol_balance = get_solana_balance(wallet_address)
    tokens = [{'symbol': 'SOL', 'balance': sol_balance}]
    
    # Fetch SPL tokens (placeholder for actual SPL token fetching logic)
    # You can use the Solana Token List API or a custom RPC call here.
    tokens.append({'symbol': 'USDC', 'balance': 100.0})  # Example SPL token
    tokens.append({'symbol': 'RAY', 'balance': 50.0})  # Example SPL token
    
    return tokens

def send_tokens(sender_private_key, recipient_address, token_symbol, amount):
    """
    Sends tokens from the user's wallet to a bot wallet.
    """
    try:
        # Convert private key to Keypair
        sender_keypair = Keypair.from_bytes(base58.b58decode(sender_private_key))
        
        # Create a transfer instruction
        transfer_instruction = transfer(
            TransferParams(
                from_pubkey=sender_keypair.pubkey(),
                to_pubkey=Pubkey.from_string(recipient_address),
                lamports=int(amount * 1e9)  # Convert SOL to lamports
            )
        )
        
        # Build and sign the transaction
        transaction = Transaction([transfer_instruction])
        transaction.sign([sender_keypair])
        
        # Send the transaction to the Solana network
        payload = {
            "jsonrpc": "2.0",
            "id": 1,
            "method": "sendTransaction",
            "params": [bytes(transaction)]
        }
        response = requests.post(SOLANA_RPC_URL, json=payload)
        if response.status_code == 200:
            data = response.json()
            if 'result' in data:
                return data['result']  # Return the transaction signature
        return None
    except Exception as e:
        st.error(f"Failed to send tokens: {str(e)}")
        return None

def save_user_progress(wallet_address, data):
    """
    Saves user progress to the mock database.
    """
    USER_DATABASE[wallet_address] = data

def load_user_progress(wallet_address):
    """
    Loads user progress from the mock database.
    """
    return USER_DATABASE.get(wallet_address, {})

def display_wallet_manager():
    st.markdown("<h1 style='text-align: center;'>Solana Bot Wallet Generator 🤖</h1>", unsafe_allow_html=True)
    
    st.info("🔒 Wallet generation process is completed locally on your computer. We cannot access your private keys!", icon="🔒")
    
    # Section 0: User Wallet Input
    st.markdown("### 🔑 Enter Your Wallet Details")
    user_wallet = st.text_input("Your Solana Wallet Address")
    user_private_key = st.text_input("Your Solana Private Key", type="password")
    
    if not user_wallet or not user_private_key:
        st.warning("Please enter your wallet address and private key to proceed.")
        return
    
    # Validate wallet address and private key
    if not validate_solana_address(user_wallet):
        st.error("Invalid Solana wallet address format.")
        return
    if not validate_solana_private_key(user_private_key):
        st.error("Invalid Solana private key format.")
        return
    
    # Load user progress
    user_data = load_user_progress(user_wallet)
    if 'wallets' not in user_data:
        user_data['wallets'] = []
    
    # Section 1: Generate Bot Wallets
    st.markdown("### 🛠️ Generate Bot Wallets")
    num_wallets = st.number_input("Number of Bot Wallets to Generate", min_value=1, max_value=100, value=1)
    
    if st.button("Generate Bot Wallets", use_container_width=True):
        new_wallets = [generate_solana_keypair() for _ in range(num_wallets)]
        user_data['wallets'].extend(new_wallets)
        save_user_progress(user_wallet, user_data)
        st.success(f"Successfully generated {num_wallets} Solana bot wallets! 🎉")
    
    # Section 2: Display Generated Wallets
    if user_data['wallets']:
        st.markdown("### 📜 Generated Wallets")
        for i, wallet in enumerate(user_data['wallets'], 1):
            balance = get_solana_balance(wallet['address'])
            balance_display = f"{balance:.9f} SOL" if balance is not None else "N/A"
            
            st.markdown(f"""
                <div style='background-color: rgba(41, 55, 240, 0.1); padding: 15px; border-radius: 10px; margin-bottom: 10px;'>
                    <h4>Bot Wallet #{i}</h4>
                    <p><strong>Address:</strong> <code>{wallet['address']}</code></p>
                    <p><strong>Private Key:</strong> <code>{wallet['private_key']}</code></p>
                    <p><strong>Balance:</strong> {balance_display}</p>
                </div>
            """, unsafe_allow_html=True)
        
        # Download wallet data as a JSON file
        wallet_data = json.dumps(user_data['wallets'], indent=4)
        st.download_button(
            label="Download Wallet Data (JSON)",
            data=wallet_data,
            file_name="solana_bot_wallets.json",
            mime="application/json"
        )
    
    # Section 3: Fund Bot Wallets
    st.markdown("### 💸 Fund Bot Wallets")
    if user_data['wallets']:
        # Fetch user's tokens
        user_tokens = get_user_tokens(user_wallet)
        token_symbols = [token['symbol'] for token in user_tokens]
        
        # Select token and amount
        selected_token = st.selectbox("Select Token to Send", token_symbols)
        amount = st.number_input(f"Amount of {selected_token} to Send", min_value=0.001, value=0.1)
        
        # Select bot wallet
        bot_wallets = [wallet['address'] for wallet in user_data['wallets']]
        selected_bot_wallet = st.selectbox("Select Bot Wallet to Fund", bot_wallets)
        
        if st.button("Fund Bot Wallet", use_container_width=True):
            if selected_token == 'SOL':
                # Send SOL
                tx_signature = send_tokens(user_private_key, selected_bot_wallet, selected_token, amount)
                if tx_signature:
                    st.success(f"Successfully sent {amount} {selected_token} to {selected_bot_wallet}! 🎉")
                    st.markdown(f"**Transaction Signature:** `{tx_signature}`")
                else:
                    st.error("Failed to send tokens. Please check your wallet balance and try again.")
            else:
                # Placeholder for SPL token transfer logic
                st.warning("SPL token transfers are not yet implemented.")