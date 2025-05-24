# -*- coding: utf-8 -*-
"""
reconlibs.py: Utility functions for the Recon Project.

This module provides core functionalities for:
- Reading and writing the application's configuration file (`recon.opts`).
- Cryptographic operations: generating Fernet keys, encrypting, and decrypting data
  for secure communication.
"""

# No socket import needed here anymore as network ops are in secure_transfer.py
# import socket
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

    Args:
        optionfile: The path to the options file (e.g., "recon.opts").

    Returns:
        A tuple containing all the configuration options:
        (server_hostname, server_port, scanner_username, scanner_password,
         ssh_port, source_data_path, recon_server_temp_path, recon_script_name,
         recon_dicom_output_dir, scanner_dicom_source_dir, log_filepath,
         shared_key, misc_options_lines)
    """
    # Default values
    default_server_hostname = 'localhost'
    default_server_port = 60000
    default_scanner_username = 'sdc'
    default_scanner_password = 'adw2.0' # Consider security implications of default passwords
    default_ssh_port = 22
    default_source_data_path = '/usr/g/mrraw/'
    default_recon_server_temp_path = '/tmp/recon_server_pfiles' # Server's PFILE download/work dir
    default_recon_script_name = 'default_recon_script.sh' # Example: matlab_script.m or python_script.py
    default_recon_dicom_output_dir = '/tmp/recon_server_dicoms' # Server's DICOM output dir (source for sending to client)
    default_scanner_dicom_source_dir = '/tmp/scanner_dicoms/' # Less relevant now, client sends PFILE
    default_log_filepath = '/tmp/recon_project.log' # Unified log file name
    default_shared_key = "SET_YOUR_SHARED_KEY_HERE" # Emphasize that this needs to be set
    default_trusted_ips = "127.0.0.1,::1" # Example for localhost IPv4 and IPv6
    default_client_pfile_name = "P00000.7"
    default_client_pfile_path = "/tmp/default_pfile_on_client/P00000.7"


    try:
        with open(optionfile, 'r') as opt_f:
            server_hostname = opt_f.readline().strip()
            server_port = int(opt_f.readline().strip())
            scanner_username = opt_f.readline().strip()
            scanner_password = opt_f.readline().strip()
            ssh_port = int(opt_f.readline().strip())
            source_data_path = opt_f.readline().strip()
            recon_server_temp_path = opt_f.readline().strip()
            recon_script_name = opt_f.readline().strip()
            recon_dicom_output_dir = opt_f.readline().strip()
            scanner_dicom_source_dir = opt_f.readline().strip()
            log_filepath = opt_f.readline().strip()
            
            shared_key_line = opt_f.readline().strip()
            if shared_key_line.startswith("SHARED_KEY ="):
                shared_key = shared_key_line.split('=', 1)[1].strip()
            else: # Handle older format or error
                print(f"Warning: SHARED_KEY line in '{optionfile}' might be malformed. Attempting to read as raw key.")
                shared_key = shared_key_line # Assume it's just the key
            
            misc_options_lines = opt_f.readlines() # Read all remaining lines for other options

    except FileNotFoundError:
        print(f"Warning: Options file '{optionfile}' not found. Creating with default values.")
        # Assign defaults for return values
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
        shared_key = default_shared_key # Will be written as placeholder
        misc_options_lines = [ # These will form the basis for the tail of the new default file
            f"# TRUSTEDIPS: {default_trusted_ips}\n",
            f"# CLIENT_DEFAULT_PFILE_NAME = {default_client_pfile_name}\n",
            f"# CLIENT_DEFAULT_PFILE_PATH = {default_client_pfile_path}\n"
        ]

        with open(optionfile, 'w') as opt_f:
            opt_f.write(f"# Recon server IP address or hostname (e.g., localhost, 192.168.1.100)\n{server_hostname}\n")
            opt_f.write(f"# Port for recon server communication (e.g., 60000)\n{server_port}\n")
            opt_f.write(f"# Username for scanner authentication (legacy, may not be used by current server)\n{scanner_username}\n")
            opt_f.write(f"# Password for scanner authentication (legacy, may not be used by current server)\n{scanner_password}\n")
            opt_f.write(f"# SSH port for secure shell access (legacy, currently unused by server_app)\n{ssh_port}\n")
            opt_f.write(f"# Path to source data (legacy, MRRAW directory, less relevant if PFILE sent by client)\n{source_data_path}\n")
            opt_f.write(f"# Server's directory for downloaded PFILEs and temporary recon files\n{recon_server_temp_path}\n")
            opt_f.write(f"# Full path or name of the reconstruction script on the server (e.g., /opt/scripts/matlab_recon.sh or python_recon.py)\n{recon_script_name}\n")
            opt_f.write(f"# Server's directory where reconstructed DICOMs are stored (and from where they are sent to client)\n{recon_dicom_output_dir}\n")
            opt_f.write(f"# Scanner's DICOM directory (legacy, less relevant if DICOMs are sent back to client)\n{scanner_dicom_source_dir}\n")
            opt_f.write(f"# Path to the log file for server and client applications\n{log_filepath}\n")
            opt_f.write(f"# --- Secure Transfer Options ---\n")
            opt_f.write(f"# SHARED_KEY: A securely generated Fernet key for encrypting transfers.\n")
            opt_f.write(f"# IMPORTANT: Generate using: python -c \"from reconlibs import generate_key; print(generate_key())\"\n")
            opt_f.write(f"# Copy the output key and paste it here, replacing the placeholder.\n")
            opt_f.write(f"# This key MUST be identical on both the client and server.\n")
            opt_f.write(f"SHARED_KEY = {shared_key}\n") # Writes the placeholder default_shared_key initially
            opt_f.write(f"# --- Server Options ---\n")
            opt_f.write(f"# TRUSTEDIPS: Comma-separated list of client IP addresses allowed to connect to the server.\n")
            opt_f.write(f"# Example: #TRUSTEDIPS: 192.168.1.101,192.168.1.102\n")
            opt_f.write(f"# If commented out or empty, the server may allow all IPs (check server_app logic).\n")
            opt_f.write(f"{misc_options_lines[0].strip()}\n") # Default TRUSTEDIPS line
            opt_f.write(f"# --- Client Options ---\n")
            opt_f.write(f"# CLIENT_DEFAULT_PFILE_NAME: Default PFILE name for the client application if not specified on command line.\n")
            opt_f.write(f"CLIENT_DEFAULT_PFILE_NAME = {default_client_pfile_name}\n")
            opt_f.write(f"# CLIENT_DEFAULT_PFILE_PATH: Default full path to the PFILE on the client machine if not specified on command line.\n")
            opt_f.write(f"CLIENT_DEFAULT_PFILE_PATH = {default_client_pfile_path}\n")
            opt_f.write(f"# --- Other Misc Options (add as KEY = VALUE or #COMMENT) ---\n")
            # Write any other misc options that were part of the default generation if needed
            for line in misc_options_lines[1:]: # Skip TRUSTEDIPS as it's handled
                if "CLIENT_DEFAULT_PFILE_NAME" not in line and "CLIENT_DEFAULT_PFILE_PATH" not in line:
                    opt_f.write(line)
        print(f"A new default options file was created at '{optionfile}'. Please review and configure it, especially SHARED_KEY.")

    except Exception as e:
        print(f"Error reading options file '{optionfile}': {e}. Returning hardcoded defaults as a last resort.")
        # Fallback to hardcoded defaults if any other error occurs during reading/writing
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
        shared_key = default_shared_key # Return the placeholder if file ops failed
        misc_options_lines = [ # Minimal misc options if all else fails
            f"# TRUSTEDIPS: {default_trusted_ips}\n",
            f"CLIENT_DEFAULT_PFILE_NAME = {default_client_pfile_name}\n",
            f"CLIENT_DEFAULT_PFILE_PATH = {default_client_pfile_path}\n"
        ]

    return (
        server_hostname, server_port, scanner_username, scanner_password,
        ssh_port, source_data_path, recon_server_temp_path, recon_script_name,
        recon_dicom_output_dir, scanner_dicom_source_dir, log_filepath,
        shared_key, misc_options_lines
    )


# Obsolete functions below are kept commented out for reference during final review,
# but will be removed. They are not used by the new secure_transfer based apps.
#
# def capture_packet(server_socket: socket.socket) -> tuple[bytes | None, socket.socket, tuple[str, int]]:
#     """DEPRECATED"""
#     pass
#
# def capture_packet_client(client_socket: socket.socket) -> bytes | None:
#     """DEPRECATED"""
#     pass
#
# def packet_to_pfile(received_data: bytes) -> tuple[str, list[str]] | tuple[None, None]:
#     """DEPRECATED"""
#     pass
#
# def args_to_str(*args: any) -> str:
#     """DEPRECATED"""
#     pass
#
# def str_to_args(input_string: str) -> list[str]:
#     """DEPRECATED"""
#     pass
#
# def get_opts_tagvals(options_lines: list[str], tag: str) -> list[str]:
#     """
#     DEPRECATED. Specific tag parsing (like TRUSTEDIPS) is now handled
#     directly in the application logic (_load_configuration in server_app.py
#     and client_app.py by iterating misc_options_lines).
#     """
#     pass
#
# # Example Python scripts (can be expanded or moved to a plugin system)
# def pyscript1(*args, **kwargs):
#     """DEPRECATED Example script 1."""
#     pass
#
# def pyscript2(*args, **kwargs):
#     """DEPRECATED Example script 2."""
#     pass
#
# # Dictionary to map script names to functions
# # This allows calling scripts by name (e.g., from network command)
# pyscripts = { # DEPRECATED
#     '1': pyscript1,
#     '2': pyscript2,
# }
