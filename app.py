import streamlit as st
import requests
import re
import pandas as pd
import base58
from eth_keys import keys
from eth_utils import decode_hex
from solana.keypair import Keypair
from datetime import datetime

# GitHub API settings
GITHUB_API_URL = "https://api.github.com/search/code"
HEADERS = {"Accept": "application/vnd.github.v3+json"}

# Improved Regex patterns for valid private keys
EVM_KEY_PATTERN = r'(?<![a-fA-F0-9])0x[a-fA-F0-9]{64}(?![a-fA-F0-9])'  # Ethereum private keys
SOL_KEY_PATTERN = r'(?<![A-Za-z0-9])[5KLMN][1-9A-HJ-NP-Za-km-z]{50,51}(?![A-Za-z0-9])'  # Solana private keys

# Function to search GitHub for leaked keys
def search_github(query, token, max_results=10):
    HEADERS["Authorization"] = f"token {token}"
    params = {"q": query, "per_page": max_results}
    response = requests.get(GITHUB_API_URL, headers=HEADERS, params=params)
    if response.status_code == 200:
        return response.json().get("items", [])
    return []

# Function to extract keys from code snippets
def extract_keys_from_code(code_snippet):
    evm_keys = re.findall(EVM_KEY_PATTERN, code_snippet)
    sol_keys = re.findall(SOL_KEY_PATTERN, code_snippet)
    return [key for key in evm_keys if is_valid_eth_key(key)], [key for key in sol_keys if is_valid_solana_key(key)]

# Validate Ethereum private key
def is_valid_eth_key(key):
    try:
        priv_key = keys.PrivateKey(decode_hex(key[2:]))  # Remove '0x' before decoding
        return True
    except:
        return False

# Validate Solana private key
def is_valid_solana_key(key):
    try:
        decoded_key = base58.b58decode(key)
        return len(decoded_key) == 32  # Solana private keys must be 32 bytes
    except:
        return False

# Streamlit UI
st.title("🔑 GitHub Leaked Key Scanner")
st.sidebar.header("Settings")

github_token = st.sidebar.text_input("GitHub API Token", type="password")
search_keyword = st.sidebar.text_input("Search Query", "private key")
num_results = st.sidebar.slider("Max Results", 5, 50, 10)
scan_button = st.sidebar.button("Scan GitHub")

# Display results
data = []
if scan_button and github_token:
    st.info("Scanning GitHub for leaked keys...")
    results = search_github(search_keyword, github_token, num_results)
    for item in results:
        repo_name = item["repository"]["full_name"]
        file_url = item["html_url"]
        raw_url = item["git_url"].replace("git://", "https://raw.githubusercontent.com/").replace("/blob/", "/")
        
        # Fetch raw code
        raw_code = requests.get(raw_url).text
        evm_keys, sol_keys = extract_keys_from_code(raw_code)
        
        for key in evm_keys:
            data.append([repo_name, file_url, "Ethereum", key])
        for key in sol_keys:
            data.append([repo_name, file_url, "Solana", key])

# Convert to DataFrame
if data:
    df = pd.DataFrame(data, columns=["Repository", "File URL", "Type", "Leaked Key"])
    st.write(df)
    st.download_button("Download as CSV", df.to_csv(index=False), "leaked_keys.csv", "text/csv")
else:
    st.warning("No valid leaked keys found. Try adjusting the search query!")
