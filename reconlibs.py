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
    default_trusted_ips = "127.0.0.1,::1" # Added for completeness in defaults

    # Define default configuration for recon.opts
    default_recon_options = {
        "SERVER_HOSTNAME": default_server_hostname,
        "SERVER_PORT": default_server_port,
        "LOG_FILEPATH": default_log_filepath,
        "SHARED_KEY": default_shared_key,
        "MAX_CONCURRENT_JOBS": default_max_concurrent_jobs,
        "RECON_SERVER_BASE_PFILE_DIR": default_recon_server_temp_path, # Renamed
        "RECON_SCRIPT_PATH": default_recon_script_name, # Renamed
        "RECON_SERVER_DICOM_OUTPUT_DIR": default_recon_dicom_output_dir, # Renamed
        "TRUSTED_IPS": default_trusted_ips,
        "CLIENT_DEFAULT_PFILE_NAME": default_client_pfile_name,
        "CLIENT_DEFAULT_PFILE_PATH": default_client_pfile_path,
        "CLIENT_DOWNLOAD_DIR": default_client_download_dir,
        # Legacy options (will be commented out in default file)
        "SCANNER_USERNAME": default_scanner_username,
        "SCANNER_PASSWORD": default_scanner_password,
        "SSH_PORT": default_ssh_port,
        "SOURCE_DATA_PATH": default_source_data_path,
        "SCANNER_DICOM_SOURCE_DIR": default_scanner_dicom_source_dir,
        # Client Daemon options (will be commented out or have defaults)
        "CLIENT_WATCH_DIRECTORY": default_client_watch_directory,
        "CLIENT_WATCH_PATTERN": default_client_watch_pattern,
        "CLIENT_DAEMON_POLL_INTERVAL": default_client_daemon_poll_interval,
        "CLIENT_DAEMON_STABILITY_DELAY": default_client_daemon_stability_delay,
        "CLIENT_DAEMON_GROUPING_TIMEOUT": default_client_daemon_grouping_timeout,
        "CLIENT_DAEMON_RECON_OPTIONS_JSON": default_client_daemon_recon_options_json,
    }

    # Define default configuration for relay.opts
    default_relay_options = {
        "RELAY_HOSTNAME": "localhost",
        "RELAY_PORT": 60001,
        "LOG_FILEPATH": "/tmp/relay_server.log",
        "SHARED_KEY_RELAY_TO_CLIENTS": "SET_YOUR_RELAY_TO_CLIENTS_KEY_HERE",
        "BACKEND_SERVERS": "localhost:60000", # Comma-separated host:port
        "TRUSTED_CLIENT_IPS": "", # Comma-separated, blank for any. Example: "127.0.0.1,192.168.1.0/24"
        # Potentially other relay-specific defaults like:
        # "RELAY_TEMP_DIR": "/tmp/relay_temp",
        # "HEALTH_CHECK_INTERVAL": 60, # seconds
        # "LOAD_BALANCING_STRATEGY": "round_robin", # or "random", "least_connections"
    }
    
    current_defaults = {}
    if optionfile == 'relay.opts':
        current_defaults = default_relay_options
    else: # Default to recon.opts behavior for any other filename
        current_defaults = default_recon_options

    options = current_defaults.copy() # Start with defaults, override with file contents

    if not os.path.exists(optionfile):
        print(f"Options file '{optionfile}' not found. Creating with default values for '{os.path.basename(optionfile)}'.")
        with open(optionfile, 'w') as opt_f:
            if optionfile == 'relay.opts':
                opt_f.write("# Relay Server Configuration\n")
                opt_f.write(f"RELAY_HOSTNAME = {current_defaults['RELAY_HOSTNAME']}\n")
                opt_f.write(f"RELAY_PORT = {current_defaults['RELAY_PORT']}\n\n")
                opt_f.write("# Logging\n")
                opt_f.write(f"LOG_FILEPATH = {current_defaults['LOG_FILEPATH']}\n\n")
                opt_f.write("# Security\n")
                opt_f.write(f"SHARED_KEY_RELAY_TO_CLIENTS = {current_defaults['SHARED_KEY_RELAY_TO_CLIENTS']}\n")
                opt_f.write("# Comma-separated list of IPs or CIDR notations. Leave blank or comment out for no IP restriction.\n")
                opt_f.write(f"#TRUSTED_CLIENT_IPS = {current_defaults.get('TRUSTED_CLIENT_IPS', '127.0.0.1,192.168.1.0/24')}\n\n") # Example in comment
                opt_f.write("# Backend Reconstruction Servers\n")
                opt_f.write("# Comma-separated list of host:port pairs (e.g., server1.example.com:60000,server2.example.com:60000)\n")
                opt_f.write(f"BACKEND_SERVERS = {current_defaults['BACKEND_SERVERS']}\n\n")
                # Add other relay-specific defaults here if any
                # opt_f.write("# Optional: Temporary directory for relay operations\n")
                # opt_f.write(f"#RELAY_TEMP_DIR = {current_defaults.get('RELAY_TEMP_DIR', '/tmp/relay_temp')}\n")
            else: # recon.opts or other files
                opt_f.write("# Server Configuration\n")
                opt_f.write(f"SERVER_HOSTNAME = {current_defaults['SERVER_HOSTNAME']}\n")
                opt_f.write(f"SERVER_PORT = {current_defaults['SERVER_PORT']}\n\n")

                opt_f.write("# Security\n")
                opt_f.write(f"SHARED_KEY = {current_defaults['SHARED_KEY']}\n")
                opt_f.write("# Comma-separated list of IPs, or leave blank for no restriction\n")
                opt_f.write(f"TRUSTED_IPS = {current_defaults['TRUSTED_IPS']}\n\n")

                opt_f.write("# Paths\n")
                opt_f.write(f"RECON_SERVER_BASE_PFILE_DIR = {current_defaults['RECON_SERVER_BASE_PFILE_DIR']}\n")
                opt_f.write(f"RECON_SCRIPT_PATH = {current_defaults['RECON_SCRIPT_PATH']}\n")
                opt_f.write(f"RECON_SERVER_DICOM_OUTPUT_DIR = {current_defaults['RECON_SERVER_DICOM_OUTPUT_DIR']}\n")
                opt_f.write(f"LOG_FILEPATH = {current_defaults['LOG_FILEPATH']}\n\n")

                opt_f.write("# Server Settings\n")
                opt_f.write(f"MAX_CONCURRENT_JOBS = {current_defaults['MAX_CONCURRENT_JOBS']}\n\n")
                
                opt_f.write("# Client Defaults\n")
                opt_f.write(f"CLIENT_DEFAULT_PFILE_NAME = {current_defaults['CLIENT_DEFAULT_PFILE_NAME']}\n")
                opt_f.write(f"CLIENT_DEFAULT_PFILE_PATH = {current_defaults['CLIENT_DEFAULT_PFILE_PATH']}\n")
                opt_f.write(f"CLIENT_DOWNLOAD_DIR = {current_defaults['CLIENT_DOWNLOAD_DIR']}\n\n")

                opt_f.write("# Legacy options (commented out or with defaults)\n")
                opt_f.write(f"# SCANNER_USERNAME = {current_defaults['SCANNER_USERNAME']}\n")
                opt_f.write(f"# SCANNER_PASSWORD = {current_defaults['SCANNER_PASSWORD']}\n")
                opt_f.write(f"# SSH_PORT = {current_defaults['SSH_PORT']}\n")
                opt_f.write(f"# SOURCE_DATA_PATH = {current_defaults['SOURCE_DATA_PATH']}\n")
                opt_f.write(f"# SCANNER_DICOM_SOURCE_DIR = {current_defaults['SCANNER_DICOM_SOURCE_DIR']}\n\n")

                opt_f.write("# Client Daemon Specific Options (for client_daemon.py)\n")
                opt_f.write("# Directory for the client daemon to monitor for new files (leave empty to disable daemon watch feature)\n")
                opt_f.write(f"CLIENT_WATCH_DIRECTORY = {current_defaults['CLIENT_WATCH_DIRECTORY']}\n") 
                opt_f.write("# File pattern for the daemon to look for in the watch directory (e.g., *.dcm, P*.7)\n")
                opt_f.write(f"CLIENT_WATCH_PATTERN = \"{current_defaults['CLIENT_WATCH_PATTERN']}\"\n") 
                opt_f.write("# Time (seconds) for daemon to wait after file detection for file to stabilize before processing\n")
                opt_f.write(f"CLIENT_DAEMON_STABILITY_DELAY = {current_defaults['CLIENT_DAEMON_STABILITY_DELAY']}\n")
                opt_f.write("# Time (seconds) for daemon to wait to group multiple files detected close together for a single job\n")
                opt_f.write(f"CLIENT_DAEMON_GROUPING_TIMEOUT = {current_defaults['CLIENT_DAEMON_GROUPING_TIMEOUT']}\n")
                opt_f.write("# Default reconstruction options (JSON string) for jobs submitted by the daemon\n")
                opt_f.write(f"CLIENT_DAEMON_RECON_OPTIONS_JSON = '{current_defaults['CLIENT_DAEMON_RECON_OPTIONS_JSON']}'\n") 
                opt_f.write("# Fallback poll interval if watchdog is not used (seconds) - Not actively used by current watchdog handler\n")
                opt_f.write(f"CLIENT_DAEMON_POLL_INTERVAL = {current_defaults['CLIENT_DAEMON_POLL_INTERVAL']}\n")

        print(f"A new default options file was created at '{optionfile}'. Please review and configure it.")
        # When file is newly created, 'options' (which is a copy of current_defaults) holds the correct defaults.
    else: # Option file exists, parse it
        # Initialize options with the correct set of defaults before parsing,
        # so that parsing only overrides what's in the file.
        if optionfile == 'relay.opts':
            options = default_relay_options.copy()
        else:
            options = default_recon_options.copy()
            
        with open(optionfile, 'r') as opt_f:
            for line_number, line_content in enumerate(opt_f, 1):
                line_content = line_content.strip()

                if not line_content or line_content.startswith("#"):
                    continue # Skip blank lines and comments

                key_value_match = re.match(r"^\s*([A-Za-z0-9_]+)\s*=\s*(.*)", line_content)
                if key_value_match:
                    key = key_value_match.group(1).strip().upper()
                    value_str = key_value_match.group(2).strip()

                    # Attempt to infer type
                    if value_str.lower() == 'true':
                        value = True
                    elif value_str.lower() == 'false':
                        value = False
                    elif value_str.isdigit() or (value_str.startswith('-') and value_str[1:].isdigit()):
                        try:
                            value = int(value_str)
                        except ValueError: # Should not happen with isdigit but as safeguard
                            value = value_str 
                    elif value_str.startswith('"') and value_str.endswith('"'):
                        value = value_str[1:-1] # Remove surrounding quotes
                    elif value_str.startswith("'") and value_str.endswith("'"):
                        value = value_str[1:-1] # Remove surrounding quotes
                    else:
                        value = value_str
                    
                    if key in options: # Update if key is known from defaults
                        options[key] = value
                    else: # A new key not in defaults
                        print(f"Warning: Unknown option '{key}' found in '{optionfile}' on line {line_number}. It will be added to the options dictionary.")
                        options[key] = value
                else:
                    print(f"Warning: Malformed line in '{optionfile}' on line {line_number}: '{line_content}'. Skipping.")
    
    # Ensure critical keys have sane values after parsing, specific to the type of option file
    if optionfile == 'relay.opts':
        if not options.get("SHARED_KEY_RELAY_TO_CLIENTS") or options["SHARED_KEY_RELAY_TO_CLIENTS"] == "SET_YOUR_RELAY_TO_CLIENTS_KEY_HERE":
            if options.get("SHARED_KEY_RELAY_TO_CLIENTS") != default_relay_options["SHARED_KEY_RELAY_TO_CLIENTS"]:
                 print(f"Warning: 'SHARED_KEY_RELAY_TO_CLIENTS' is not configured or still set to placeholder in '{optionfile}'. THIS IS INSECURE.")
            options["SHARED_KEY_RELAY_TO_CLIENTS"] = default_relay_options["SHARED_KEY_RELAY_TO_CLIENTS"]
        if not isinstance(options.get("RELAY_PORT"), int):
            print(f"Warning: RELAY_PORT is missing or invalid. Using default {default_relay_options['RELAY_PORT']}.")
            options["RELAY_PORT"] = default_relay_options['RELAY_PORT']
        if not options.get("BACKEND_SERVERS"): # Must have at least one backend
             print(f"Warning: 'BACKEND_SERVERS' is not configured in '{optionfile}'. Using default '{default_relay_options['BACKEND_SERVERS']}'.")
             options["BACKEND_SERVERS"] = default_relay_options['BACKEND_SERVERS']

    else: # recon.opts and other files
        if not options.get("SHARED_KEY") or options["SHARED_KEY"] == "SET_YOUR_SHARED_KEY_HERE":
            if options.get("SHARED_KEY") != default_recon_options["SHARED_KEY"]: 
                 print(f"Warning: 'SHARED_KEY' is not configured or still set to placeholder in '{optionfile}'. THIS IS INSECURE.")
            options["SHARED_KEY"] = default_recon_options["SHARED_KEY"] 

        if not isinstance(options.get("SERVER_PORT"), int):
            print(f"Warning: SERVER_PORT is missing or invalid. Using default {default_recon_options['SERVER_PORT']}.")
            options["SERVER_PORT"] = default_recon_options['SERVER_PORT']
            
        if not isinstance(options.get("MAX_CONCURRENT_JOBS"), int):
            mcj_val = options.get("MAX_CONCURRENT_JOBS", default_recon_options['MAX_CONCURRENT_JOBS'])
            print(f"Warning: MAX_CONCURRENT_JOBS is missing or invalid ('{mcj_val}'). Using default {default_recon_options['MAX_CONCURRENT_JOBS']}.")
            options["MAX_CONCURRENT_JOBS"] = default_recon_options['MAX_CONCURRENT_JOBS']
        elif options["MAX_CONCURRENT_JOBS"] <= 0:
            print(f"Warning: MAX_CONCURRENT_JOBS must be positive (was {options['MAX_CONCURRENT_JOBS']}). Using default {default_recon_options['MAX_CONCURRENT_JOBS']}.")
            options["MAX_CONCURRENT_JOBS"] = default_recon_options['MAX_CONCURRENT_JOBS']


    return options

```
