import streamlit as st
import requests
import re
import pandas as pd
import base58
from eth_keys import keys
from eth_utils import decode_hex
from datetime import datetime
import time

# GitHub API settings
GITHUB_API_URL = "https://api.github.com/search/repositories"
HEADERS = {"Accept": "application/vnd.github.v3+json"}

# Regex patterns for valid private keys and seed phrases
CRYPTO_PATTERNS = {
    "Ethereum": r'0x[a-fA-F0-9]{64}',  # Strict Ethereum private key format
    "Solana": r'[5KLMN][1-9A-HJ-NP-Za-km-z]{51,52}',  # Solana private key (base58)
    "Bitcoin": r'[5KL][1-9A-HJ-NP-Za-km-z]{51,52}',  # Bitcoin private key
    "Seed Phrase": r'\b(?:[a-z]{3,8}\s){11,23}[a-z]{3,8}\b',  # 12-24 words
    "Wallet JSON": r'\{.*("crypto"|"wallet"|"address"|"privateKey").*\}'  # JSON format
}


# Function to check GitHub API token validity
def check_github_token(token):
    HEADERS["Authorization"] = f"token {token}"
    response = requests.get("https://api.github.com/user", headers=HEADERS)
    return response.status_code == 200

# Function to search GitHub for repositories
def search_github_repos(query, token, max_results=5):
    HEADERS["Authorization"] = f"token {token}"
    params = {"q": query, "per_page": max_results}
    response = requests.get(GITHUB_API_URL, headers=HEADERS, params=params)
    if response.status_code == 200:
        return response.json().get("items", [])
    return []

# Function to extract keys from code
def extract_keys_from_code(code_snippet):
    found_keys = {}
    for key_type, pattern in CRYPTO_PATTERNS.items():
        found_keys[key_type] = re.findall(pattern, code_snippet)
    return found_keys

# Function to get the default branch of a repository
def get_default_branch(repo_name, token):
    url = f"https://api.github.com/repos/{repo_name}"
    HEADERS["Authorization"] = f"token {token}"
    response = requests.get(url, headers=HEADERS)
    if response.status_code == 200:
        return response.json().get("default_branch", "main")
    return "main"

# Function to scan all files in a repository
def scan_repository(repo_name, repo_url, token):
    branch = get_default_branch(repo_name, token)
    files_url = f"https://api.github.com/repos/{repo_name}/git/trees/{branch}?recursive=1"
    HEADERS["Authorization"] = f"token {token}"
    response = requests.get(files_url, headers=HEADERS)
    
    if response.status_code != 200:
        return []
    
    files = response.json().get("tree", [])
    data = []
    
    for file in files:
        if file["type"] == "blob":
            raw_url = f"https://raw.githubusercontent.com/{repo_name}/{branch}/{file['path']}"
            try:
                raw_code = requests.get(raw_url).text
                found_keys = extract_keys_from_code(raw_code)
                
                for key_type, keys in found_keys.items():
                    for key in keys:
                        data.append([repo_name, raw_url, key_type, key])
                        st.sidebar.write(f"🔑 Found {key_type} key in {repo_name}")
                        return data  # Stop scanning once a valid key is found
            except:
                continue
    return data

# Streamlit UI
st.title("🔑 GitHub Crypto Key & Seed Phrase Scanner")
st.sidebar.header("Settings")

github_token = st.sidebar.text_input("GitHub API Token", type="password")
search_keyword = st.sidebar.text_input("Search Queries (comma-separated)", "private key, seed phrase, wallet")
num_results = st.sidebar.slider("Max Repositories", 1, 20, 5)
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
        repos = search_github_repos(query, github_token, num_results)
        for repo in repos:
            repo_name = repo["full_name"]
            repo_url = repo["html_url"]
            
            if repo_name in scanned_repos:
                continue
            
            scanned_repos.append(repo_name)
            st.sidebar.write(f"📂 Scanning: {repo_name}")
            
            results = scan_repository(repo_name, repo_url, github_token)
            if results:
                data.extend(results)
                break  # Stop searching after finding the first valid key

if data:
    df = pd.DataFrame(data, columns=["Repository", "File URL", "Type", "Leaked Key"])
    st.write(df)
    st.download_button("Download as CSV", df.to_csv(index=False), "leaked_keys.csv", "text/csv")
else:
    st.warning("No valid leaked keys found. Try adjusting the search query!")

st.sidebar.subheader("Scanned Repositories")
st.sidebar.write(scanned_repos if scanned_repos else "No repositories scanned yet.")
