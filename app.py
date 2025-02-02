import streamlit as st
import requests
import re
import pandas as pd
import base58
from eth_keys import keys
from eth_utils import decode_hex

# GitHub API settings
GITHUB_API_URL = "https://api.github.com/search/repositories"
HEADERS = {"Accept": "application/vnd.github.v3+json"}

# Your Etherscan API key (replace with your actual key)
ETHERSCAN_API_KEY = "YOUR_ETHERSCAN_API_KEY"

# Regex patterns for private keys and seed phrases
CRYPTO_PATTERNS = {
    "Ethereum": r'0x[a-fA-F0-9]{64}',
    "Solana": r'[5KLMN][1-9A-HJ-NP-Za-km-z]{51,52}',
    "Seed Phrase": r'\b(?:[a-z]{3,8}\s){11,23}[a-z]{3,8}\b',
}

# Check Ethereum balance
def get_ethereum_balance(address):
    url = f"https://api.etherscan.io/api?module=account&action=balance&address={address}&tag=latest&apikey={ETHERSCAN_API_KEY}"
    response = requests.get(url).json()
    balance = response.get("result", "0")
    return int(balance) > 0  # Return True if balance > 0

# Check Solana balance
def get_solana_balance(address):
    url = f"https://public-api.solscan.io/account/tokens?account={address}"
    response = requests.get(url).json()
    if response.get("data"):
        return True  # Return True if balance exists
    return False

# Validate Ethereum private key
def is_valid_ethereum_private_key(private_key):
    try:
        key = keys.PrivateKey(decode_hex(private_key))
        address = key.public_key.to_checksum_address()
        return get_ethereum_balance(address)  # Check balance
    except Exception:
        return False

# Validate Solana private key
def is_valid_solana_private_key(private_key):
    try:
        decoded_key = base58.b58decode(private_key)
        address = base58.b58encode(decoded_key).decode()
        return get_solana_balance(address)  # Check balance
    except Exception:
        return False

# Extract crypto keys and seed phrases from code
def extract_keys_from_code(code_snippet):
    found_keys = {}
    for key_type, pattern in CRYPTO_PATTERNS.items():
        found_keys[key_type] = re.findall(pattern, code_snippet)
    return found_keys

# Other functions remain the same...

# Scan repository function
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
                        if key_type == "Ethereum":
                            if is_valid_ethereum_private_key(key):
                                data.append([repo_name, raw_url, key_type, key])
                                st.write(f"🔑 Found Ethereum Key: {key} in {repo_name}!")
                        elif key_type == "Solana":
                            if is_valid_solana_private_key(key):
                                data.append([repo_name, raw_url, key_type, key])
                                st.write(f"🔑 Found Solana Key: {key} in {repo_name}!")

            except Exception as e:
                continue

    return data

# Streamlit UI remains the same...



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
    st.info("🔍 Scanning GitHub for leaked crypto keys...")
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

if data:
    df = pd.DataFrame(data, columns=["Repository", "File URL", "Type", "Leaked Key"])
    
    # Mask the leaked key (show only first 4 and last 4 characters)
    df["Leaked Key (Masked)"] = df["Leaked Key"].apply(lambda x: x[:4] + "..." + x[-4:])
    
    st.write(df.drop(columns=["Leaked Key"]))  # Hide full key by default
    
    if st.button("🔓 Reveal Full Keys (Security Risk)"):
        st.write(df)  # Show full unmasked keys
    
    st.download_button("⬇️ Download as CSV", df.to_csv(index=False), "leaked_keys.csv", "text/csv")
else:
    st.warning("No valid leaked keys found. Try adjusting the search query!")

st.sidebar.subheader("Scanned Repositories")
st.sidebar.write(scanned_repos if scanned_repos else "No repositories scanned yet.")
