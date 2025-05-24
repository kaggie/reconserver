# -*- coding: utf-8 -*-
"""
reconlibs.py: Utility functions for the Recon Project.

This module provides core functionalities for:
- Reading and writing the application's configuration file (`recon.opts`).
- Cryptographic operations: generating Fernet keys, encrypting, and decrypting data
  for secure communication.
"""
import os
import re # For parsing key-value pairs
from cryptography.fernet import Fernet, InvalidToken

# To generate a new key for recon.opts:
# from reconlibs import generate_key
# print(generate_key())
# Copy the output string and paste it into the SHARED_KEY field in your recon.opts file.
# Ensure this key is identical on both the client and server.
def generate_key() -> str:
    """Generates a new Fernet key and returns it in base64 encoded string format."""
    key = Fernet.generate_key()
    return key.decode('utf-8')


def encrypt_data(data: bytes, key_string: str) -> bytes:
    """Encrypts data using a base64 encoded Fernet key string.

    Args:
        data: The bytes to encrypt.
        key_string: The base64 encoded Fernet key.

    Returns:
        The encrypted data as bytes.
    """
    key = key_string.encode('utf-8')
    f = Fernet(key)
    return f.encrypt(data)


def decrypt_data(encrypted_data: bytes, key_string: str) -> bytes | None:
    """Decrypts data using a base64 encoded Fernet key string.

    Args:
        encrypted_data: The bytes to decrypt.
        key_string: The base64 encoded Fernet key.

    Returns:
        The decrypted data as bytes, or None if decryption fails.
    """
    key = key_string.encode('utf-8')
    f = Fernet(key)
    try:
        return f.decrypt(encrypted_data)
    except InvalidToken:
        print("Error: Decryption failed. Invalid token or key.")
        return None


### TRY READING AN OPTION FILE.  WRITE DEFAULT OPTIONS IF FILE DOES NOT EXIST
def readoptions(optionfile: str):
    """
    Reads options from the specified file.
    Writes default options if the file does not exist.
    Order of returned values (20 elements):
    0: server_hostname (str)
    1: server_port (int)
    2: scanner_username (str) - Legacy
    3: scanner_password (str) - Legacy
    4: ssh_port (int) - Legacy
    5: source_data_path (str) - Legacy
    6: recon_server_temp_path (str) - Server's PFILE download/work dir (base for job dirs)
    7: recon_script_name (str) - Main recon script on server
    8: recon_dicom_output_dir (str) - Server's DICOM output dir
    9: scanner_dicom_source_dir (str) - Legacy
    10: log_filepath (str) - Common log file path for client and server apps
    11: shared_key (str)
    12: max_concurrent_jobs (int) - Server setting
    13: client_watch_directory (str) - Daemon setting
    14: client_watch_pattern (str) - Daemon setting
    15: client_daemon_poll_interval (int) - Daemon setting (seconds, fallback)
    16: client_daemon_stability_delay (int) - Daemon setting (seconds)
    17: client_daemon_grouping_timeout (int) - Daemon setting (seconds)
    18: client_daemon_recon_options_json (str) - Daemon setting (JSON string)
    19: misc_options_lines (list[str]) - Unparsed/comment lines from the end of the file
    """
    # Default values for primary options
    default_server_hostname = 'localhost'
    default_server_port = 60000
    default_scanner_username = 'sdc' 
    default_scanner_password = 'adw2.0'
    default_ssh_port = 22 
    default_source_data_path = '/usr/g/mrraw/' 
    default_recon_server_temp_path = '/tmp/recon_server_pfiles'
    default_recon_script_name = 'default_recon_script.sh'
    default_recon_dicom_output_dir = '/tmp/recon_server_dicoms'
    default_scanner_dicom_source_dir = '/tmp/scanner_dicoms/' 
    default_log_filepath = '/tmp/recon_project.log' 
    default_shared_key = "SET_YOUR_SHARED_KEY_HERE"
    default_max_concurrent_jobs = 1
    
    # Defaults for client app (can be overridden by misc options in recon.opts)
    default_client_pfile_name = "P00000.7"
    default_client_pfile_path = "/tmp/default_pfile_on_client/P00000.7"
    default_client_download_dir = "client_downloads"

    # Defaults for new client daemon options
    default_client_watch_directory = "" 
    default_client_watch_pattern = "*.7"
    default_client_daemon_poll_interval = 10  # Not actively used by watchdog version but good for reference
    default_client_daemon_stability_delay = 5 
    default_client_daemon_grouping_timeout = 5
    default_client_daemon_recon_options_json = "{}"
    default_trusted_ips = "127.0.0.1,::1"

    # Initialize variables with primary defaults
    server_hostname = default_server_hostname
    server_port = default_server_port
    scanner_username = default_scanner_username
    scanner_password = default_scanner_password
    ssh_port = default_ssh_port
    source_data_path = default_source_data_path
    recon_server_temp_path = default_recon_server_temp_path
    recon_script_name = default_recon_script_name
    recon_dicom_output_dir = default_recon_dicom_output_dir
    scanner_dicom_source_dir = default_scanner_dicom_source_dir
    log_filepath = default_log_filepath
    shared_key = default_shared_key
    max_concurrent_jobs = default_max_concurrent_jobs
    
    # Initialize daemon options with their defaults
    client_watch_directory = default_client_watch_directory
    client_watch_pattern = default_client_watch_pattern
    client_daemon_poll_interval = default_client_daemon_poll_interval 
    client_daemon_stability_delay = default_client_daemon_stability_delay
    client_daemon_grouping_timeout = default_client_daemon_grouping_timeout
    client_daemon_recon_options_json = default_client_daemon_recon_options_json
    
    misc_options_lines_final_list = [] # For storing unparsed lines

    if not os.path.exists(optionfile):
        print(f"Options file '{optionfile}' not found. Creating with default values.")
        with open(optionfile, 'w') as opt_f:
            opt_f.write(f"# Recon server IP address or hostname (e.g., localhost, 192.168.1.100)\n{default_server_hostname}\n")
            opt_f.write(f"# Port for recon server communication (e.g., 60000)\n{default_server_port}\n")
            opt_f.write(f"# Username for scanner authentication (legacy, may not be used by current server)\n{default_scanner_username}\n")
            opt_f.write(f"# Password for scanner authentication (legacy, may not be used by current server)\n{default_scanner_password}\n")
            opt_f.write(f"# SSH port for secure shell access (legacy, currently unused by server_app)\n{default_ssh_port}\n")
            opt_f.write(f"# Path to source data (legacy, MRRAW directory, less relevant if PFILE sent by client)\n{default_source_data_path}\n")
            opt_f.write(f"# Server's directory for downloaded PFILEs and temporary recon files (base for job dirs)\n{default_recon_server_temp_path}\n")
            opt_f.write(f"# Full path or name of the reconstruction script on the server (e.g., /opt/scripts/matlab_recon.sh or python_recon.py)\n{default_recon_script_name}\n")
            opt_f.write(f"# Server's directory where reconstructed DICOMs are stored (and from where they are sent to client)\n{default_recon_dicom_output_dir}\n")
            opt_f.write(f"# Scanner's DICOM directory (legacy, less relevant if DICOMs are sent back to client)\n{default_scanner_dicom_source_dir}\n")
            opt_f.write(f"# Path to the log file for server and client applications\n{default_log_filepath}\n")
            opt_f.write(f"# --- Secure Transfer Options ---\n")
            opt_f.write(f"SHARED_KEY = {default_shared_key}\n")
            opt_f.write(f"# --- Server Specific Options ---\n")
            opt_f.write(f"MAX_CONCURRENT_JOBS = {default_max_concurrent_jobs}\n")
            opt_f.write(f"# --- Client Application Specific Options (some can be overridden by client_app.py CLI) ---\n")
            opt_f.write(f"CLIENT_DEFAULT_PFILE_NAME = {default_client_pfile_name}\n")
            opt_f.write(f"CLIENT_DEFAULT_PFILE_PATH = {default_client_pfile_path}\n")
            opt_f.write(f"CLIENT_DOWNLOAD_DIR = {default_client_download_dir}\n")
            opt_f.write(f"# --- Client Daemon Specific Options (for client_daemon.py) ---\n")
            opt_f.write(f"# Directory for the client daemon to monitor for new files (leave empty to disable daemon watch feature)\n")
            opt_f.write(f"#CLIENT_WATCH_DIRECTORY = {default_client_watch_directory}\n")
            opt_f.write(f"# File pattern for the daemon to look for in the watch directory (e.g., *.dcm, P*.7)\n")
            opt_f.write(f"#CLIENT_WATCH_PATTERN = {default_client_watch_pattern}\n")
            opt_f.write(f"# Time (seconds) for daemon to wait after file detection for file to stabilize before processing\n")
            opt_f.write(f"#CLIENT_DAEMON_STABILITY_DELAY = {default_client_daemon_stability_delay}\n")
            opt_f.write(f"# Time (seconds) for daemon to wait to group multiple files detected close together for a single job\n")
            opt_f.write(f"#CLIENT_DAEMON_GROUPING_TIMEOUT = {default_client_daemon_grouping_timeout}\n")
            opt_f.write(f"# Default reconstruction options (JSON string) for jobs submitted by the daemon\n")
            opt_f.write(f"#CLIENT_DAEMON_RECON_OPTIONS_JSON = {default_client_daemon_recon_options_json}\n")
            opt_f.write(f"# Fallback poll interval if watchdog is not used (seconds) - Not actively used by current watchdog handler\n")
            opt_f.write(f"#CLIENT_DAEMON_POLL_INTERVAL = {default_client_daemon_poll_interval}\n")
            opt_f.write(f"# --- Other Miscellaneous Options & Comments (e.g., TRUSTEDIPS) ---\n")
            opt_f.write(f"#TRUSTEDIPS = {default_trusted_ips}\n") # Example
        print(f"A new default options file was created at '{optionfile}'. Please review and configure it.")
        # Populate misc_options_lines for the return tuple when file is newly created
        misc_options_lines_final_list.append(f"#TRUSTEDIPS = {default_trusted_ips}")
        misc_options_lines_final_list.append(f"CLIENT_DEFAULT_PFILE_NAME = {default_client_pfile_name}")
        misc_options_lines_final_list.append(f"CLIENT_DEFAULT_PFILE_PATH = {default_client_pfile_path}")
        misc_options_lines_final_list.append(f"CLIENT_DOWNLOAD_DIR = {default_client_download_dir}")
        # Daemon options are not added to misc_options_lines_final_list here as they are returned explicitly

    else: # Option file exists, parse it
        with open(optionfile, 'r') as opt_f:
            lines = [line.strip() for line in opt_f.readlines()]

        # Parse fixed-position options first (up to log_filepath)
        if len(lines) > 0: server_hostname = lines[0]
        if len(lines) > 1: server_port = int(lines[1])
        if len(lines) > 2: scanner_username = lines[2]
        if len(lines) > 3: scanner_password = lines[3]
        if len(lines) > 4: ssh_port = int(lines[4])
        if len(lines) > 5: source_data_path = lines[5]
        if len(lines) > 6: recon_server_temp_path = lines[6]
        if len(lines) > 7: recon_script_name = lines[7]
        if len(lines) > 8: recon_dicom_output_dir = lines[8]
        if len(lines) > 9: scanner_dicom_source_dir = lines[9]
        if len(lines) > 10: log_filepath = lines[10]
        
        current_line_idx = 11 # Start of K-V or misc options
        
        parsed_keys_from_file = set() # To track if primary K-V like SHARED_KEY were found

        for i in range(current_line_idx, len(lines)):
            line_content = lines[i]
            if not line_content.strip() or line_content.strip().startswith("#"):
                misc_options_lines_final_list.append(line_content)
                continue

            key_value_match = re.match(r"^\s*([A-Za-z0-9_]+)\s*=\s*(.*)", line_content)
            if key_value_match:
                key = key_value_match.group(1).strip().upper()
                value = key_value_match.group(2).strip()
                
                is_primary_kv = True # Flag to check if it's a primary parsed option for the return tuple
                if key == "SHARED_KEY": shared_key = value; parsed_keys_from_file.add(key)
                elif key == "MAX_CONCURRENT_JOBS":
                    try: max_concurrent_jobs = int(value); parsed_keys_from_file.add(key)
                    except ValueError: print(f"Warning: Invalid MAX_CONCURRENT_JOBS value '{value}'. Using default {default_max_concurrent_jobs}.")
                elif key == "CLIENT_WATCH_DIRECTORY": client_watch_directory = value; parsed_keys_from_file.add(key)
                elif key == "CLIENT_WATCH_PATTERN": client_watch_pattern = value; parsed_keys_from_file.add(key)
                elif key == "CLIENT_DAEMON_POLL_INTERVAL":
                    try: client_daemon_poll_interval = int(value); parsed_keys_from_file.add(key)
                    except ValueError: print(f"Warning: Invalid CLIENT_DAEMON_POLL_INTERVAL '{value}'. Using default {default_client_daemon_poll_interval}.")
                elif key == "CLIENT_DAEMON_STABILITY_DELAY":
                    try: client_daemon_stability_delay = int(value); parsed_keys_from_file.add(key)
                    except ValueError: print(f"Warning: Invalid CLIENT_DAEMON_STABILITY_DELAY '{value}'. Using default {default_client_daemon_stability_delay}.")
                elif key == "CLIENT_DAEMON_GROUPING_TIMEOUT":
                    try: client_daemon_grouping_timeout = int(value); parsed_keys_from_file.add(key)
                    except ValueError: print(f"Warning: Invalid CLIENT_DAEMON_GROUPING_TIMEOUT '{value}'. Using default {default_client_daemon_grouping_timeout}.")
                elif key == "CLIENT_DAEMON_RECON_OPTIONS_JSON": client_daemon_recon_options_json = value; parsed_keys_from_file.add(key)
                # Client app specific defaults are also parsed as K-V if present
                elif key in ["CLIENT_DEFAULT_PFILE_NAME", "CLIENT_DEFAULT_PFILE_PATH", "CLIENT_DOWNLOAD_DIR", "TRUSTEDIPS"]:
                     # These are not primary returned values for the daemon tuple but might be in recon.opts
                     # They will be added to misc_options_lines_final_list
                     misc_options_lines_final_list.append(line_content) 
                     is_primary_kv = False 
                else:
                    is_primary_kv = False 
                
                if not is_primary_kv : # If not one of the explicitly parsed K-V, add to misc
                     misc_options_lines_final_list.append(line_content)
            else: 
                 misc_options_lines_final_list.append(line_content) # Not a K-V, add to misc
        
        # Fallback for very old format SHARED_KEY/MAX_CONCURRENT_JOBS (no longer explicitly supported for simplicity)
        # Users should adopt K-V for these. If not found via K-V, defaults will be used.
        if shared_key == default_shared_key and not any("SHARED_KEY" in line.upper() for line in lines[11:] if "=" in line): # Check if SHARED_KEY was parsed as K-V
            print(f"Warning: 'SHARED_KEY = <key>' not found in '{optionfile}'. Using default placeholder. THIS IS INSECURE.")
        if max_concurrent_jobs == default_max_concurrent_jobs and not any("MAX_CONCURRENT_JOBS" in line.upper() for line in lines[11:] if "=" in line): # Check if MAX_CONCURRENT_JOBS was parsed as K-V
             print(f"Info: 'MAX_CONCURRENT_JOBS = <value>' not found. Using default: {default_max_concurrent_jobs}.")


    return (
        server_hostname, server_port, scanner_username, scanner_password,
        ssh_port, source_data_path, recon_server_temp_path, recon_script_name,
        recon_dicom_output_dir, scanner_dicom_source_dir, log_filepath,
        shared_key, max_concurrent_jobs,
        client_watch_directory, client_watch_pattern, client_daemon_poll_interval,
        client_daemon_stability_delay, client_daemon_grouping_timeout, 
        client_daemon_recon_options_json,
        misc_options_lines_final_list 
    )

```
