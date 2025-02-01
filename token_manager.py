import streamlit as st
from solders.keypair import Keypair
from solders.pubkey import Pubkey
from solders.rpc.api import Client
from solders.transaction import Transaction
from spl.token.client import Token
from spl.token.constants import TOKEN_PROGRAM_ID

# Solana RPC endpoint
SOLANA_RPC_URL = "https://api.mainnet-beta.solana.com"
client = Client(SOLANA_RPC_URL)

def create_spl_token(wallet, private_key, name, symbol, decimals, initial_supply):
    """Create a new SPL token."""
    try:
        # Convert private key to Keypair
        keypair = Keypair.from_bytes(base58.b58decode(private_key))
        
        # Create the token
        token = Token.create_mint(
            conn=client,
            payer=keypair,
            mint_authority=keypair.pubkey(),
            decimals=decimals,
            program_id=TOKEN_PROGRAM_ID,
        )
        
        # Create associated token account
        associated_token_account = token.create_associated_token_account(keypair.pubkey())
        
        # Mint initial supply
        token.mint_to(
            dest=associated_token_account,
            mint_authority=keypair,
            amount=initial_supply * (10 ** decimals),
        )
        
        return token.pubkey, associated_token_account
    except Exception as e:
        st.error(f"Failed to create token: {str(e)}")
        return None, None

def display_token_manager():
    st.markdown("<h1 style='text-align: center;'>Solana Token Creator 🚀</h1>", unsafe_allow_html=True)
    
    col1, col2 = st.columns([2, 1])
    
    with col1:
        token_name = st.text_input("Token Name", placeholder="Enter your token name")
        token_symbol = st.text_input("Token Symbol", placeholder="Enter token symbol")
        decimals = st.number_input("Decimals", min_value=0, max_value=9, value=9)
        supply = st.number_input("Supply", min_value=1, value=1000000)
        
        token_description = st.text_area("Token Description", placeholder="Describe your token")
        
        st.markdown("### Social Links")
        website = st.text_input("Website", placeholder="https://")
        twitter = st.text_input("Twitter", placeholder="https://twitter.com/")
        telegram = st.text_input("Telegram", placeholder="https://t.me/")
        
    with col2:
        st.markdown("### Token Logo")
        uploaded_file = st.file_uploader(
            "Click to Upload", 
            type=['png', 'gif', 'jpg', 'webp', 'jpeg'],
            help="Recommended size: 1000×1000 pixels"
        )
        
        if uploaded_file:
            st.image(uploaded_file, width=200)
            
        st.markdown("### Security Settings")
        revoke_update = st.checkbox("Revoke Update (Immutable)", 
            help="Renouncing ownership means you will not be able to modify the token metadata")
        
        revoke_freeze = st.checkbox("Revoke Freeze", 
            help="Revoking Freeze Authority removes control over specific account actions")
        
        revoke_mint = st.checkbox("Revoke Mint", 
            help="Relinquishing minting rights prevents further token supply creation")

    st.markdown("<br>", unsafe_allow_html=True)
    
    col1, col2, col3 = st.columns([1, 2, 1])
    with col2:
        if st.button("Create Token", use_container_width=True):
            with st.spinner("Creating your token..."):
                # Token creation logic here
                token_pubkey, associated_account = create_spl_token(
                    st.session_state.wallet,
                    st.session_state.private_key,
                    token_name,
                    token_symbol,
                    decimals,
                    supply
                )
                if token_pubkey:
                    st.success(f"Token {token_symbol} created successfully! 🎉")
                    st.info(f"Token Address: `{token_pubkey}`")
                    st.info(f"Associated Token Account: `{associated_account}`")