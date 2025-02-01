import streamlit as st
import requests
import re
import pandas as pd
import base58
from eth_keys import keys
from eth_utils import decode_hex

# GitHub API settings
GITHUB_API_URL = "https://api.github.com/search/code"
HEADERS = {"Accept": "application/vnd.github.v3+json"}

# Improved Regex patterns for valid private keys
EVM_KEY_PATTERN = r'(?<![a-fA-F0-9])0x[a-fA-F0-9]{64}(?![a-fA-F0-9])'
SOL_KEY_PATTERN = r'(?<![A-Za-z0-9])[5KLMN][1-9A-HJ-NP-Za-km-z]{50,51}(?![A-Za-z0-9])'

# Function to search GitHub for leaked keys
def search_github(query, token, max_results=50):
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

# Streamlit UI
st.title("🔑 GitHub Leaked Key Scanner")
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
            download_url = item["download_url"]  # Use download_url directly
            
            st.write(f"Fetching raw code from: {download_url}")
            try:
                raw_code = requests.get(download_url).text
                evm_keys, sol_keys = extract_keys_from_code(raw_code)
                
                for key in evm_keys:
                    data.append([repo_name, file_url, "Ethereum", key])
                    st.success(f"Found Ethereum key: {key}")
                for key in sol_keys:
                    data.append([repo_name, file_url, "Solana", key])
                    st.success(f"Found Solana key: {key}")
            except Exception as e:
                st.warning(f"Could not fetch code from {file_url}: {e}")

# Convert to DataFrame
if data:
    df = pd.DataFrame(data, columns=["Repository", "File URL", "Type", "Leaked Key"])
    st.write(df)
    st.download_button("Download as CSV", df.to_csv(index=False), "leaked_keys.csv", "text/csv")
else:
    st.warning("No valid leaked keys found. Try adjusting the search query!")
