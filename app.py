import streamlit as st
import requests
import re
import pandas as pd
import base58
from eth_keys import keys
from eth_utils import decode_hex

# GitHub API settings
GITHUB_API_URL = "https://api.github.com/search/code"
USER_API_URL = "https://api.github.com/user"
HEADERS = {"Accept": "application/vnd.github.v3+json"}

# Improved Regex patterns for valid private keys
EVM_KEY_PATTERN = r'(?<![a-fA-F0-9])0x[a-fA-F0-9]{64}(?![a-fA-F0-9])'
SOL_KEY_PATTERN = r'(?<![A-Za-z0-9])[5KLMN][1-9A-HJ-NP-Za-km-z]{50,51}(?![A-Za-z0-9])'

# Function to validate GitHub API token
def validate_github_token(token):
    HEADERS["Authorization"] = f"token {token}"
    response = requests.get(USER_API_URL, headers=HEADERS)
    return response.status_code == 200

# Function to search GitHub for repositories containing the search keyword
def search_github(query, token, max_results=100, page=1):
    HEADERS["Authorization"] = f"token {token}"
    params = {"q": query, "per_page": max_results, "page": page}
    response = requests.get(GITHUB_API_URL, headers=HEADERS, params=params)
    if response.status_code == 200:
        return response.json().get("items", [])
    return []

# Function to extract keys from code snippets
def extract_keys_from_code(code_snippet):
    evm_keys = re.findall(EVM_KEY_PATTERN, code_snippet)
    sol_keys = re.findall(SOL_KEY_PATTERN, code_snippet)
    return evm_keys, sol_keys

# Validate Ethereum private key
def is_valid_eth_key(key):
    try:
        priv_key = keys.PrivateKey(decode_hex(key[2:]))  # Remove '0x' before decoding
        return True
    except Exception:
        return False

# Validate Solana private key
def is_valid_solana_key(key):
    try:
        decoded_key = base58.b58decode(key)
        return len(decoded_key) in [32, 64]  # Solana private keys are typically 32 or 64 bytes
    except Exception:
        return False

# Function to get raw file content from the repository
def get_raw_file_content(repo_name, path, token):
    raw_url = f"https://raw.githubusercontent.com/{repo_name}/main/{path}"
    headers = {"Authorization": f"token {token}"}
    response = requests.get(raw_url, headers=headers)
    if response.status_code == 200:
        return response.text
    return ""

# Streamlit UI
st.set_page_config(page_title="🔑 GitHub Leaked Key Scanner", layout="wide")
st.title("🔑 GitHub Leaked Key Scanner")
st.sidebar.header("Settings")

github_token = st.sidebar.text_input("GitHub API Token", type="password")
search_keywords = st.sidebar.text_area("Search Queries (comma-separated)", "private key")
num_results = st.sidebar.slider("Max Results per Query", 5, 100, 10)
scan_button = st.sidebar.button("Scan GitHub")

# Validate the GitHub API token immediately
if github_token:
    if validate_github_token(github_token):
        st.sidebar.success("Valid GitHub API Token!")
    else:
        st.sidebar.error("Invalid GitHub API Token. Please check and try again.")

# Initialize session state for scanned repositories
if 'searched_repos' not in st.session_state:
    st.session_state.searched_repos = set()

# Display results
data = []
if scan_button and github_token:
    st.info("Scanning GitHub for leaked keys...")
    with st.spinner("Searching..."):
        for search_keyword in search_keywords.split(","):
            search_keyword = search_keyword.strip()  # Clean up the keyword
            page = 1
            while True:
                results = search_github(search_keyword, github_token, num_results, page)
                if not results:
                    break  # Exit loop if no more results
                
                for item in results:
                    repo_name = item["repository"]["full_name"]
                    path = item["path"]
                    if repo_name in st.session_state.searched_repos:
                        continue  # Skip already searched repositories
                    
                    st.session_state.searched_repos.add(repo_name)  # Mark as searched
                    st.write(f"Scanning repository: {repo_name}")

                    # Get the raw file content for the found code
                    raw_code = get_raw_file_content(repo_name, path, github_token)
                    evm_keys, sol_keys = extract_keys_from_code(raw_code)

                    # Check for valid keys
                    for key in evm_keys:
                        if is_valid_eth_key(key):
                            data.append([repo_name, item["html_url"], "Ethereum", key])
                            st.success(f"Found valid Ethereum key: {key}")
                            break  # Stop searching upon finding a valid key
                    if data:  # If a valid key has been found, exit the loop
                        break
                    
                    for key in sol_keys:
                        if is_valid_solana_key(key):
                            data.append([repo_name, item["html_url"], "Solana", key])
                            st.success(f"Found valid Solana key: {key}")
                            break  # Stop searching upon finding a valid key
                    if data:  # If a valid key has been found, exit the loop
                        break
                
                page += 1  # Go to the next page of results

# Convert to DataFrame
if data:
    df = pd.DataFrame(data, columns=["Repository", "File URL", "Type", "Leaked Key"])
    st.write(df)
    st.download_button("Download as CSV", df.to_csv(index=False), "leaked_keys.csv", "text/csv")
else:
    st.warning("No valid leaked keys found. Try adjusting the search query!")
