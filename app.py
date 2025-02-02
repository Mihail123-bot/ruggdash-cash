import streamlit as st
import requests
import re
import pandas as pd
import base58
from eth_keys import keys
from eth_utils import decode_hex
from datetime import datetime

# GitHub API settings
GITHUB_API_URL = "https://api.github.com/search/code"
HEADERS = {"Accept": "application/vnd.github.v3+json"}

# Regex patterns for valid private keys and seed phrases
CRYPTO_PATTERNS = {
    "Ethereum": r'(?<![a-fA-F0-9])0x[a-fA-F0-9]{64}(?![a-fA-F0-9])',
    "Solana": r'(?<![A-Za-z0-9])[5KLMN][1-9A-HJ-NP-Za-km-z]{50,51}(?![A-Za-z0-9])',
    "Bitcoin": r'(?<![A-Za-z0-9])[5KL][1-9A-HJ-NP-Za-km-z]{50,51}(?![A-Za-z0-9])',
    "Seed Phrase": r'([a-z]+ ){11,23}[a-z]+',
}

# Function to check GitHub API token validity
def check_github_token(token):
    HEADERS["Authorization"] = f"token {token}"
    response = requests.get("https://api.github.com/user", headers=HEADERS)
    return response.status_code == 200

# Function to search GitHub for leaked keys
def search_github(query, token, max_results=10):
    HEADERS["Authorization"] = f"token {token}"
    params = {"q": query, "per_page": max_results}
    response = requests.get(GITHUB_API_URL, headers=HEADERS)
    if response.status_code == 200:
        return response.json().get("items", [])
    return []

# Function to extract keys from code snippets
def extract_keys_from_code(code_snippet):
    found_keys = {}
    for key_type, pattern in CRYPTO_PATTERNS.items():
        found_keys[key_type] = re.findall(pattern, code_snippet)
    return found_keys

# Streamlit UI
st.title("🔑 GitHub Crypto Key & Seed Phrase Scanner")
st.sidebar.header("Settings")

github_token = st.sidebar.text_input("GitHub API Token", type="password")
search_keyword = st.sidebar.text_input("Search Queries (comma-separated)", "private key, seed phrase, wallet")
num_results = st.sidebar.slider("Max Results", 5, 50, 10)
scan_button = st.sidebar.button("Scan GitHub")

if github_token:
    if check_github_token(github_token):
        st.success("✅ GitHub API Token is valid!")
    else:
        st.error("❌ Invalid GitHub API Token!")
        st.stop()

data = []
scanned_repos = []
if scan_button and github_token:
    st.info("Scanning GitHub for leaked crypto keys...")
    queries = [q.strip() for q in search_keyword.split(",")]
    for query in queries:
        results = search_github(query, github_token, num_results)
        for item in results:
            repo_name = item["repository"]["full_name"]
            file_url = item["html_url"]
            raw_url = item.get("download_url")
            
            if not raw_url or repo_name in scanned_repos:
                continue

            scanned_repos.append(repo_name)
            raw_code = requests.get(raw_url).text
            found_keys = extract_keys_from_code(raw_code)
            
            for key_type, keys in found_keys.items():
                for key in keys:
                    data.append([repo_name, file_url, key_type, key])

if data:
    df = pd.DataFrame(data, columns=["Repository", "File URL", "Type", "Leaked Key"])
    st.write(df)
    st.download_button("Download as CSV", df.to_csv(index=False), "leaked_keys.csv", "text/csv")
else:
    st.warning("No valid leaked keys found. Try adjusting the search query!")

st.sidebar.subheader("Scanned Repositories")
st.sidebar.write(scanned_repos if scanned_repos else "No repositories scanned yet.")
