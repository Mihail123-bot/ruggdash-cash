import streamlit as st
import requests
import re
import pandas as pd
import base58
from eth_keys import keys
from eth_utils import decode_hex

# GitHub API settings
GITHUB_API_URL = "https://mainnet.infura.io/v3/6e34ed8d853f4abb83516b5a3a51df0c"
HEADERS = {"Accept": "application/vnd.github.v3+json"}

# Crypto private key patterns
EVM_KEY_PATTERN = r'(?<![a-fA-F0-9])0x[a-fA-F0-9]{64}(?![a-fA-F0-9])'
SOL_KEY_PATTERN = r'(?<![A-Za-z0-9])[5KLMN][1-9A-HJ-NP-Za-km-z]{50,51}(?![A-Za-z0-9])'
BTC_KEY_PATTERN = r'5[HJK][1-9A-Za-z]{49}'  # Example pattern for Bitcoin

# Validate Ethereum private key
def is_valid_eth_key(key):
    try:
        priv_key = keys.PrivateKey(decode_hex(key[2:]))
        return True
    except:
        return False

# Validate Solana private key
def is_valid_solana_key(key):
    try:
        decoded_key = base58.b58decode(key)
        return len(decoded_key) in [32, 64]
    except:
        return False

# Function to check GitHub token validity
def is_valid_github_token(token):
    HEADERS["Authorization"] = f"token {token}"
    response = requests.get("https://api.github.com/user", headers=HEADERS)
    return response.status_code == 200

# Function to search GitHub
def search_github(query, token, max_results=10):
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
    btc_keys = re.findall(BTC_KEY_PATTERN, code_snippet)
    
    return (
        [key for key in evm_keys if is_valid_eth_key(key)],
        [key for key in sol_keys if is_valid_solana_key(key)],
        btc_keys
    )

# Streamlit UI
st.title("🔑 GitHub Crypto Key Scanner")
st.sidebar.header("Settings")

github_token = st.sidebar.text_input("GitHub API Token", type="password")
if github_token and not is_valid_github_token(github_token):
    st.sidebar.error("Invalid GitHub API Token!")
    st.stop()

search_queries = ["private key", "ethereum private key", "solana wallet", "btc wallet", "mnemonic"]
num_results = st.sidebar.slider("Max Results per Query", 5, 50, 10)
scan_button = st.sidebar.button("Start Scanning")

# Display results
data = []
if scan_button and github_token:
    st.info("Scanning GitHub for leaked keys...")
    for query in search_queries:
        results = search_github(query, github_token, num_results)
        for item in results:
            repo_name = item["repository"]["full_name"]
            file_url = item["html_url"]
            raw_url = item.get("download_url", "")
            
            if raw_url:
                raw_code = requests.get(raw_url).text
                evm_keys, sol_keys, btc_keys = extract_keys_from_code(raw_code)
                
                for key in evm_keys:
                    data.append([repo_name, file_url, "Ethereum", key])
                for key in sol_keys:
                    data.append([repo_name, file_url, "Solana", key])
                for key in btc_keys:
                    data.append([repo_name, file_url, "Bitcoin", key])

if data:
    df = pd.DataFrame(data, columns=["Repository", "File URL", "Type", "Leaked Key"])
    st.write(df)
    st.download_button("Download as CSV", df.to_csv(index=False), "leaked_keys.csv", "text/csv")
else:
    st.warning("No valid leaked keys found. Try adjusting the search query!")
