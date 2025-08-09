import os
import re
import shutil
import tempfile
import zipfile
from typing import List, Optional
import logging as log
log.basicConfig(level=log.CRITICAL, format='%(asctime)s - %(levelname)s - %(message)s')
import requests


class Peer():
    def __init__(self, proto, 
                 addr, port, 
                 region, country, 
                 is_alive=False, latency=-1, 
                 key=None, network='internet', 
                 proxy=None
    ):
        self.proto = proto
        self.addr = addr
        self.port = port
        self.region = region
        self.country = country
        self.is_alive = is_alive
        self.latency = latency # from proto tests and hidden services, can not be -1
        self.ping_latency = latency # from ping tests, can be -1 or 60000
        self.key = key
        self.network = network # values: 'internet', 'onion' for tor, 'b32.i2p' for i2p
        self.proxy = proxy
    
    def get_uri(self, key=False) -> str:
        if self.network == 'internet':
            uri = self.proto+"://"+self.addr+":"+self.port
            if key and self.key != '':
                return uri+"?key="+self.key
            else:
                return uri
        else:
            return f"socks://{self.proxy}/{self.addr}.{self.network}:{self.port}"
    
    def __str__(self):
        return self.get_uri(key=True)
    
    def get_row(self):
        return (self.get_uri(key=False), self.region, self.country, self.latency, self.ping_latency)
    

def process_zip_from_url(
    zip_url: str,
    files_to_remove: Optional[List[str]] = None,
    dirs_to_remove: Optional[List[str]] = None,
) -> List[Peer]:
    """
    Downloads and processes a ZIP file from a URL.

    Args:
        zip_url: The URL of the .zip file to download.
        regex_pattern: The raw regex string to match against lines in files.
        files_to_remove: A list of relative paths to files to remove after extraction.
        dirs_to_remove: A list of relative paths to directories to remove after extraction.

    Returns:
        A list of all lines from all files that matched the regex pattern.
        
    Raises:
        requests.exceptions.RequestException: If the download fails.
        zipfile.BadZipFile: If the downloaded file is not a valid zip file.
    """
    # Use lists for iteration, handling the optional None case
    files_to_remove = files_to_remove or []
    dirs_to_remove = dirs_to_remove or []
    peer_list: List[Tuple(str,str,str)] = []

    # Compile the regex for efficiency in the loop
    regex_pattern = r"(tcp|tls|quic|ws|wss|socks)://([a-z0-9\.\-:\[\]]+):([0-9]+)[\?key=]*([0-9a-f]*)"
    compiled_regex = re.compile(regex_pattern)
    # to capture tor and i2p
    regex2 = r"(socks)://([a-z0-9\.\-:\[\]]+):([0-9]+)[/]+([0-9a-z]+)\.(onion|b32.i2p):*([0-9]*)"
    compiled_regex_hidden = re.compile(regex2)
    
    # Create a secure temporary directory that will be automatically cleaned up
    with tempfile.TemporaryDirectory() as temp_dir:
        zip_path = os.path.join(temp_dir, 'downloaded_file.zip')
        extract_path = os.path.join(temp_dir, 'extracted_data')
        os.makedirs(extract_path)

        # 1. Download the file from the URL
        log.info(f"⬇️  Downloading from {zip_url}...")
        with requests.get(zip_url, stream=True) as response:
            response.raise_for_status()  # Raise an exception for bad status codes (4xx or 5xx)
            with open(zip_path, 'wb') as f:
                for chunk in response.iter_content(chunk_size=8192):
                    f.write(chunk)
        log.debug("✅ Download complete.")

        # 2. Extract the ZIP file
        log.debug(f"📦 Unzipping file to temporary location...")
        with zipfile.ZipFile(zip_path, 'r') as zip_ref:
            zip_ref.extractall(extract_path)
        log.debug("✅ Extraction complete.")

        # 3. Remove specified files and directories
        log.debug("🗑️  Cleaning up specified files and directories...")
        # Remove files
        for file_path in files_to_remove:
            full_path = os.path.join(extract_path, file_path)
            try:
                os.remove(full_path)
                log.debug(f"  - Removed file: {full_path}")
            except FileNotFoundError:
                log.debug(f"  - Warning: File not found, skipping: {full_path}")
            except Exception as e:
                log.debug(f"  - Error removing file {full_path}: {e}")

        # Remove directories
        for dir_path in dirs_to_remove:
            full_path = os.path.join(extract_path, dir_path)
            try:
                shutil.rmtree(full_path)
                log.debug(f"  - Removed directory: {full_path}")
            except FileNotFoundError:
                log.debug(f"  - Warning: Directory not found, skipping: {full_path}")
            except Exception as e:
                log.debug(f"  - Error removing directory {full_path}: {e}")
        log.debug("✅ Cleanup complete.")
        
        # 4. Iterate through all files, read lines, and check against regex
        log.debug("🔍 Searching for regex matches...")
        for root, _, files in os.walk(extract_path):
            for filename in files:
                file_path = os.path.join(root, filename)
                try:
                    # Open file with robust encoding handling
                    with open(file_path, 'r', encoding='utf-8', errors='ignore') as f:
                        for line in f:
                            matches_in_line = compiled_regex.findall(line)
                            if not matches_in_line:
                                continue
                            
                            for match in matches_in_line:
                                # `match` is a string if 1 group, a tuple if multiple groups
                                if isinstance(match, tuple):
                                    # Add all non-empty captured groups from the tuple
                                    if match[0] != 'socks':
                                        p = Peer(match[0], # proto
                                                 match[1], # addr
                                                 match[2], # port
                                                 os.path.basename(root), # region
                                                 filename[:-3], # country
                                                 key=match[3],
                                                 network='internet' 
                                       )
                                    else:
                                        matches_hidden = compiled_regex_hidden.findall(line)
                                        for mh in matches_hidden:
                                            if isinstance(mh, tuple):
                                                p = Peer('tcp',
                                                         mh[3], # addr
                                                         mh[5] if mh[5] != '' else '0', # port
                                                         'hidden',
                                                         'unknown',
                                                         network=mh[4],
                                                         proxy=mh[1]+':'+mh[2]
                                                )
                                            else:
                                                raise ValueError(f"Malformed peer line address: '{match}'")
                                        
                                    peer_list.append(p)
                                else:
                                    raise ValueError(f"Malformed peer line address: '{match}'")
                except Exception as e:
                    log.debug(f"  - Could not read file {file_path}: {e}")
        
        log.debug(f"✅ Search complete. Found {len(peer_list)} matches.")
    # The temporary directory and its contents are automatically removed here
    return peer_list


def get_peers():
    TARGET_URL = "https://github.com/yggdrasil-network/public-peers/archive/refs/heads/master.zip"

    FILES_TO_DELETE = ["public-peers-master/README.md", "peers.zip"]
    DIRS_TO_DELETE = ["public-peers-master/.github"]

    try:
        results = process_zip_from_url(
            zip_url=TARGET_URL,
            files_to_remove=FILES_TO_DELETE,
            dirs_to_remove=DIRS_TO_DELETE,
        )
        if results:
            return results
        else:
            log.debug("No lines matched the regex pattern.")
            return None
    except Exception as e:
        log.debug(f"\nAn error occurred: {e}")
    return None

if __name__ == "__main__":
    for peer in get_peers():
        print(peer)

