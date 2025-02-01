import streamlit as st
import requests
import re
import pandas as pd
import base58
from eth_keys import keys
from eth_utils import decode_hex
from web3 import Web3

# Ethereum RPC Setup (Infura)
INFURA_URL = "https://mainnet.infura.io/v3/6e34ed8d853f4abb83516b5a3a51df0c"  # Replace with your Infura key
w3 = Web3(Web3.HTTPProvider(INFURA_URL))

# Solana RPC Setup
SOLANA_RPC = "https://api.mainnet-beta.solana.com"

# GitHub API settings
GITHUB_API_URL = "https://api.github.com/search/code"
HEADERS = {"Accept": "application/vnd.github.v3+json"}

# Regex patterns for private keys
EVM_KEY_PATTERN = r'(?<![a-fA-F0-9])0x[a-fA-F0-9]{64}(?![a-fA-F0-9])'
SOL_KEY_PATTERN = r'(?<![A-Za-z0-9])[5KLMN][1-9A-HJ-NP-Za-km-z]{50,51}(?![A-Za-z0-9])'

# Function to search GitHub
def search_github(query, token, max_results=50):
    HEADERS["Authorization"] = f"token {token}"
    params = {"q": query, "per_page": max_results}
    response = requests.get(GITHUB_API_URL, headers=HEADERS, params=params)
    if response.status_code == 200:
        return response.json().get("items", [])
    return []

# Extract keys from code
def extract_keys_from_code(code_snippet):
    evm_keys = re.findall(EVM_KEY_PATTERN, code_snippet)
    sol_keys = re.findall(SOL_KEY_PATTERN, code_snippet)
    return [key for key in evm_keys if is_valid_eth_key(key)], [key for key in sol_keys if is_valid_solana_key(key)]

# Validate Ethereum key
def is_valid_eth_key(key):
    try:
        priv_key = keys.PrivateKey(decode_hex(key[2:]))
        return True
    except:
        return False

# Validate Solana key
def is_valid_solana_key(key):
    try:
        decoded_key = base58.b58decode(key)
        return len(decoded_key) in [32, 64]
    except:
        return False

# Convert Ethereum private key to address
def get_eth_address(private_key):
    priv_key = keys.PrivateKey(decode_hex(private_key[2:]))
    return priv_key.public_key.to_checksum_address()

# Get Ethereum balance
def get_eth_balance(private_key):
    try:
        address = get_eth_address(private_key)
        balance_wei = w3.eth.get_balance(address)
        balance_eth = w3.from_wei(balance_wei, 'ether')
        return balance_eth
    except:
        return "Error"

# Convert Solana private key to address
def get_solana_address(private_key):
    try:
        decoded_key = base58.b58decode(private_key)
        return base58.b58encode(decoded_key[:32]).decode()
    except:
        return None

# Get Solana balance
def get_solana_balance(private_key):
    try:
        address = get_solana_address(private_key)
        response = requests.get(f"{SOLANA_RPC}/v1/accounts/{address}")
        if response.status_code == 200:
            balance = response.json().get("result", {}).get("value", 0) / 10**9
            return balance
    except:
        return "Error"
    return 0

# Streamlit UI
st.title("🔑 GitHub Leaked Key Scanner with Balance Check")
st.sidebar.header("Settings")

github_token = st.sidebar.text_input("GitHub API Token", type="password")
search_queries = st.sidebar.text_input("Search Queries (comma-separated)", "0x, 5K, private key")
num_results = st.sidebar.slider("Max Results", 5, 100, 10)
scan_button = st.sidebar.button("Scan GitHub")

# Display results
data = []
if scan_button and github_token:
    queries = [q.strip() for q in search_queries.split(",")]
    for query in queries:
        st.info(f"Scanning GitHub for '{query}'...")
        results = search_github(query, github_token, num_results)

        for item in results:
            repo_name = item["repository"]["full_name"]
            file_path = item["path"]
            file_url = item["html_url"]
            download_url = item.get("download_url")

            # Construct raw file URL if missing
            if not download_url:
                default_branch = item["repository"].get("default_branch", "main")
                download_url = f"https://raw.githubusercontent.com/{repo_name}/{default_branch}/{file_path}"

            st.write(f"Fetching raw code from: {download_url}")
            try:
                raw_code = requests.get(download_url).text
                evm_keys, sol_keys = extract_keys_from_code(raw_code)

                for key in evm_keys:
                    balance = get_eth_balance(key)
                    data.append([repo_name, file_url, "Ethereum", key, balance])
                    st.success(f"Found Ethereum key: {key} | Balance: {balance} ETH")

                for key in sol_keys:
                    balance = get_solana_balance(key)
                    data.append([repo_name, file_url, "Solana", key, balance])
                    st.success(f"Found Solana key: {key} | Balance: {balance} SOL")

            except Exception as e:
                st.warning(f"Could not fetch code from {file_url}: {e}")

# Convert to DataFrame
if data:
    df = pd.DataFrame(data, columns=["Repository", "File URL", "Type", "Leaked Key", "Balance"])
    st.write(df)
    st.download_button("Download as CSV", df.to_csv(index=False), "leaked_keys.csv", "text/csv")
else:
    st.warning("No valid leaked keys found. Try adjusting the search query!")
