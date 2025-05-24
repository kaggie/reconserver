# -*- coding: utf-8 -*-
"""
client_app.py: Main application for the Recon Client.

Communicates with the ReconServerApp using SecureFileTransferClient,
responds to server commands, sends PFILEs, and receives results.
"""
import os
import socket
import subprocess
import json # For client_recon_options, though not strictly needed if passing dict
import base64 # For handling file_chunk data
import traceback

try:
    from reconlibs import readoptions
    from secure_transfer import SecureFileTransferClient
except ImportError:
    print("CRITICAL ERROR: Could not import reconlibs or secure_transfer. Ensure they are in PYTHONPATH.")
    # Provide dummy readoptions if reconlibs is missing, to allow basic structural checks if needed.
    if 'readoptions' not in globals():
        def readoptions(optionfile: str):
            print(f"Warning: Using placeholder readoptions due to missing reconlibs for '{optionfile}'. Critical features will fail.")
            return ('localhost', 60000, 'user', 'pass', 22, '/tmp_client_source', 
                    '/tmp_client_recon_files', 'client_script.sh', '/tmp_client_recon_dicom',
                    '/tmp_client_scanner_dicom', '/tmp_client.log', 
                    "dummy_shared_key_client", []) # shared_key, misc_options_lines
    if 'SecureFileTransferClient' not in globals():
        # This is a fatal error for the application's functionality.
        raise ImportError("SecureFileTransferClient is missing. Application cannot run.")

import time # For logging timestamp


class ReconClientApp:
    """
    Reconstruction Client Application.
    Connects to the ReconServer, sends PFILE information and the PFILE itself,
    and receives reconstructed DICOMs.
    """
    DEBUG = True # Enables more verbose output, can be made configurable

    def __init__(self, options_file: str = "recon.opts"):
        self.options_file = options_file
        # Initialize attributes with default types or values
        self.server_hostname: str = "localhost"
        self.server_port: int = 60000
        self.shared_key: str = ""
        self.log_filepath: str = "/tmp/recon_client.log" # Default, overridden by recon.opts
        self.client_default_pfile_name: str = "P00000.7"
        self.client_default_pfile_path: str = "/tmp/P00000.7" # Full path for the default PFILE
        
        self._load_configuration() # Load and override defaults

        self.sf_client = SecureFileTransferClient(
            host=self.server_hostname,
            port=self.server_port,
            shared_key=self.shared_key
        )
        self.client_download_dir: str = "client_downloads" # Directory for DICOMs from server
        os.makedirs(self.client_download_dir, exist_ok=True)
        
        # State for receiving files (e.g., DICOMs) from the server
        self._receiving_server_file_info: dict | None = None 

        # Attributes to be set by the run method, based on PFILE to process
        self.pfile_to_process_name: str | None = None
        self.pfile_to_process_full_path: str | None = None
        self.client_recon_options: dict | None = None

        self._log_message(f"ReconClientApp initialized. Will download received files to: {os.path.abspath(self.client_download_dir)}", is_debug=False)
        if not self.shared_key or self.shared_key == "SET_YOUR_SHARED_KEY_HERE":
            self._log_message("CRITICAL WARNING: Shared key is not set or is using the default placeholder. Secure communication is compromised.", is_error=True)
            # Consider raising an error if a valid key is absolutely mandatory for operation.
            # raise ValueError("A valid SHARED_KEY must be configured in recon.opts for secure client operation.")

    def _log_message(self, message: str, is_error: bool = False, is_debug: bool = False):
        """Helper for logging messages to console and optionally to a file."""
        log_entry = f"[{time.asctime()}] [ClientApp] {message}"
        if is_error:
            print(f"ERROR: {log_entry}")
        elif is_debug and not self.DEBUG:
            return 
        else:
            print(log_entry)
        
        try:
            with open(self.log_filepath, 'a') as lf:
                lf.write(log_entry + "\n")
        except IOError as e:
            print(f"Warning: Could not write to client log file {self.log_filepath}: {e}")

    def _load_configuration(self):
        """Loads configuration from the options file."""
        self._log_message(f"Loading configuration from '{self.options_file}'...", is_debug=True)
        try:
            # Unpack all values, assign to _ for unused ones from client's perspective
            (
                self.server_hostname, self.server_port, 
                _scan_user, _scan_pass, _ssh_port, 
                _src_data, _srv_tmp_path, _srv_script, _srv_dicom_out, _scan_dicom_src,
                self.log_filepath, # Use the log_filepath from recon.opts
                self.shared_key, misc_options_lines
            ) = readoptions(self.options_file)

            client_opts_dict = {}
            for line in misc_options_lines:
                line = line.strip()
                if line.startswith("#") or "=" not in line:
                    continue
                key, value = line.split("=", 1)
                client_opts_dict[key.strip().upper()] = value.strip()
            
            self.client_default_pfile_name = client_opts_dict.get('CLIENT_DEFAULT_PFILE_NAME', self.client_default_pfile_name)
            self.client_default_pfile_path = client_opts_dict.get('CLIENT_DEFAULT_PFILE_PATH', self.client_default_pfile_path)
            # Example: self.some_other_client_config = client_opts_dict.get('MY_CLIENT_OPTION', 'defaultValue')

            if not self.shared_key or self.shared_key == "SET_YOUR_SHARED_KEY_HERE":
                 self._log_message("SHARED_KEY is missing, empty, or using the default placeholder in recon.opts.", is_error=True)
                 # This state is checked again in __init__ for a more critical warning.

            self._log_message("Client configuration loaded successfully:", is_debug=True)
            self._log_message(f"  Server Hostname: {self.server_hostname}, Port: {self.server_port}", is_debug=True)
            self._log_message(f"  Default PFILE Name: {self.client_default_pfile_name}", is_debug=True)
            self._log_message(f"  Default PFILE Path: {self.client_default_pfile_path}", is_debug=True)
            self._log_message(f"  Client DICOM Download Dir: {self.client_download_dir}", is_debug=True)
            self._log_message(f"  Log File: {self.log_filepath}", is_debug=True)
            shared_key_status = "LOADED" if self.shared_key and self.shared_key != "SET_YOUR_SHARED_KEY_HERE" else "NOT SET or PLACEHOLDER (CRITICAL!)"
            self._log_message(f"  Shared Key Status: {shared_key_status}", is_debug=True)

        except FileNotFoundError:
            self._log_message(f"ERROR: Options file '{self.options_file}' not found. Cannot load configuration.", is_error=True)
            raise # Re-raise to be caught by main exception handler
        except Exception as e:
            self._log_message(f"ERROR: Could not load configuration from '{self.options_file}': {e}", is_error=True)
            traceback.print_exc()
            raise # Re-raise

    def _execute_local_script(self, script_name: str, params: dict | None = None) -> bool:
        """
        Placeholder for executing a script on the client machine.
        Sends status back to the server.
        """
        self._log_message(f"Placeholder: Would execute local script '{script_name}' with params: {params}", is_debug=True)
        # Example:
        # try:
        #     subprocess.run(["python", script_name, ...], check=True)
        #     status_payload = {"script_name": script_name, "status": "completed", "detail": "Client executed script successfully."}
        #     success = True
        # except Exception as e:
        #     status_payload = {"script_name": script_name, "status": "failed", "detail": str(e)}
        #     success = False
        # self.sf_client._send_message("script_execution_status", status_payload)
        # return success
        
        # For placeholder:
        status_payload = {"script_name": script_name, "status": "completed_placeholder", "detail": "Client executed script (placeholder)."}
        return self.sf_client._send_message("script_execution_status", status_payload)


    def _handle_file_reception_from_server(self, msg_type: str, payload: dict) -> bool:
        """
        Manages the state machine for receiving a file from the server.
        This is used for DICOMs or other files server might send.

        Args:
            msg_type: The type of the message from the server.
            payload: The payload of the message.
        
        Returns:
            True if file reception is ongoing/successful for this message, 
            False if a critical error occurred or transfer finished.
        """
        if msg_type == "file_transfer_start":
            filename = payload.get("filename")
            filesize = payload.get("size")
            if not filename or filesize is None:
                self._log_message(f"Invalid 'file_transfer_start' from server: {payload}", is_error=True)
                self.sf_client._send_message("ack_file_transfer_start", {"filename": filename, "status": "error", "detail": "Invalid metadata from client."})
                return False # Critical error in protocol

            # Sanitize filename to prevent path traversal issues, though os.path.join should handle it for basename
            safe_filename = os.path.basename(filename)
            filepath = os.path.join(self.client_download_dir, safe_filename)
            
            try:
                # Ensure any previous state is cleared before starting a new file
                if self._receiving_server_file_info and self._receiving_server_file_info.get("file_obj"):
                    if not self._receiving_server_file_info["file_obj"].closed:
                         self._receiving_server_file_info["file_obj"].close()
                    self._log_message(f"Warning: Overwriting previous '_receiving_server_file_info' state.", is_debug=True)

                self._receiving_server_file_info = {
                    "filepath": filepath,
                    "file_obj": open(filepath, "wb"),
                    "remaining_bytes": filesize,
                    "filename": safe_filename # Use sanitized name
                }
                self._log_message(f"Server sending file '{safe_filename}' ({filesize} bytes). Receiving to '{filepath}'.")
                self.sf_client._send_message("ack_file_transfer_start", {"filename": safe_filename, "status": "ready"})
            except IOError as e:
                self._log_message(f"IOError opening file '{filepath}' for write on client: {e}", is_error=True)
                self.sf_client._send_message("ack_file_transfer_start", {"filename": safe_filename, "status": "error", "detail": f"Client IOError: {e}"})
                self._receiving_server_file_info = None 
                return False # Cannot proceed with this file
            return True

        elif msg_type == "file_chunk":
            if not self._receiving_server_file_info or not self._receiving_server_file_info.get("file_obj"):
                self._log_message(f"Received 'file_chunk' from server but not in a valid receiving state. Payload: {payload}", is_error=True)
                # Optionally send error to server. For robustness, client might just ignore.
                return False # Indicates a protocol error or out-of-sync state

            file_info = self._receiving_server_file_info
            try:
                chunk_data_b64 = payload.get("data")
                if chunk_data_b64 is None:
                     raise ValueError("File chunk from server contained no data.")
                chunk_data = base64.b64decode(chunk_data_b64.encode('utf-8'))
                file_info["file_obj"].write(chunk_data)
                file_info["remaining_bytes"] -= len(chunk_data)
                self._log_message(f"Received chunk for {file_info['filename']}, {file_info['remaining_bytes']} bytes remaining.", is_debug=True)
            except (TypeError, base64.binascii.Error, ValueError, IOError) as e:
                self._log_message(f"Error processing 'file_chunk' from server for {file_info.get('filename', 'unknown file')}: {e}", is_error=True)
                if not file_info["file_obj"].closed: file_info["file_obj"].close()
                if os.path.exists(file_info["filepath"]): os.remove(file_info["filepath"]) 
                self._receiving_server_file_info = None
                # Notify server of error? Could be complex if server is mid-send.
                return False # Error processing chunk is critical for this file
            return True

        elif msg_type == "file_transfer_end":
            if not self._receiving_server_file_info or not self._receiving_server_file_info.get("file_obj"):
                self._log_message(f"Received 'file_transfer_end' from server but not in a valid state. Payload: {payload}", is_error=True)
                self.sf_client._send_message("ack_file_transfer_end", {"filename": payload.get("filename"), "status": "error", "detail": "Client not ready for file_transfer_end"})
                return False # Protocol error

            file_info = self._receiving_server_file_info
            ended_filename = payload.get("filename")

            if file_info.get("filename") != ended_filename:
                self._log_message(f"'file_transfer_end' for '{ended_filename}', but was receiving '{file_info.get('filename')}'. Protocol error.", is_error=True)
                self.sf_client._send_message("ack_file_transfer_end", {"filename": ended_filename, "status": "error", "detail": "Filename mismatch at client."})
                if not file_info["file_obj"].closed: file_info["file_obj"].close()
                if os.path.exists(file_info["filepath"]): os.remove(file_info["filepath"])
                self._receiving_server_file_info = None
                return False # Critical error

            if not file_info["file_obj"].closed: file_info["file_obj"].close()
            
            if file_info.get("remaining_bytes", 0) > 0:
                 self._log_message(f"Warning: File transfer ended for '{ended_filename}', but {file_info['remaining_bytes']} bytes were still expected.", is_debug=True)
            
            self._log_message(f"File '{ended_filename}' received successfully from server into '{file_info['filepath']}'.")
            self.sf_client._send_message("ack_file_transfer_end", {"filename": ended_filename, "status": "success"})
            self._receiving_server_file_info = None # Important: Clear state for next file
            return True # File transfer complete and ack sent, but listening continues for other messages.

        return False # Should not be reached if types are handled above.


    def handle_server_command(self, message: dict) -> bool:
        """
        Handles messages received from the server.
        Returns True to continue listening, False to stop.
        """
        msg_type = message.get("type")
        payload = message.get("payload", {})
        self._log_message(f"Received message from server: Type='{msg_type}', Payload='{payload}'", is_debug=True)

        if msg_type == "command":
            command_name = payload.get("command_name")
            params = payload.get("params", {})
            self._log_message(f"Processing server command: '{command_name}' with params: {params}")

            if command_name == "get_recon_details":
                if not self.pfile_to_process_name or not self.pfile_to_process_full_path:
                    self._log_message("Error: PFILE details not set in client for 'get_recon_details'. Cannot respond.", is_error=True)
                    error_payload = {"error": "PFILE details not available on client for processing."}
                    self.sf_client._send_message("recon_details_response", error_payload) # Inform server
                    return False # Critical error, stop client

                response_payload = {
                    "pfile_name": self.pfile_to_process_name,
                    "path_on_client": self.pfile_to_process_full_path,
                    "client_recon_options": self.client_recon_options or {}
                }
                self._log_message(f"Sending 'recon_details_response': {response_payload}", is_debug=True)
                self.sf_client._send_message("recon_details_response", response_payload)

            elif command_name == "execute_local_script":
                script_to_run = params.get("script_name")
                script_params = params.get("script_params")
                if script_to_run:
                    self._execute_local_script(script_to_run, script_params)
                else:
                    self._log_message("Error: 'execute_local_script' command missing 'script_name'.", is_error=True)
                    self.sf_client._send_message("ack_command", {"status": "error_missing_param", "command": command_name, "detail": "script_name not provided."})
            
            elif command_name == "dicom_transfer_start":
                num_files = payload.get("num_files", 0)
                self._log_message(f"Server is about to send {num_files} DICOM file(s). Preparing to receive.")
                self.sf_client._send_message("ack_command", {"status": "ready_for_dicoms", "command": command_name, "num_files": num_files})
            
            else: # Unknown commands from server
                self._log_message(f"Unknown server command received: {command_name}. Ignoring.", is_debug=True)
                self.sf_client._send_message("ack_command", {"status": "unknown_command", "command": command_name, "detail": "Client does not recognize this command."})

        elif msg_type == "request_file": # Server is requesting a file from this client
            filepath_to_send = payload.get("filepath")
            if filepath_to_send:
                self._log_message(f"Server requested file: '{filepath_to_send}'. Attempting to send...", is_debug=True)
                if os.path.exists(filepath_to_send):
                    if not self.sf_client.send_file(filepath_to_send):
                        self._log_message(f"Failed to send file '{filepath_to_send}' to server.", is_error=True)
                        # sf_client.send_file() handles its own error reporting to console.
                        # Optionally, notify server of client-side send failure if protocol supports it.
                else:
                    self._log_message(f"File '{filepath_to_send}' not found on client. Notifying server.", is_error=True)
                    self.sf_client._send_message("error_request_file", {"filepath": filepath_to_send, "detail": "File not found on client."})
            else:
                self._log_message("Invalid 'request_file' message from server: missing 'filepath'.", is_error=True)
        
        elif msg_type in ["file_transfer_start", "file_chunk", "file_transfer_end"]:
            if not self._handle_file_reception_from_server(msg_type, payload):
                # If _handle_file_reception_from_server returns False, it means a critical error
                # during file transfer that requires stopping or specific error handling.
                # For now, we'll log it and continue listening for other messages unless it was a fatal disconnect.
                self._log_message(f"Error during file reception for message type '{msg_type}'. Check previous logs.", is_error=True)
                # If self.sf_client.socket is None after this, it means connection died.
                if not self.sf_client.socket:
                    return False # Stop listening

        elif msg_type == "recon_complete":
            pfile_processed = payload.get("pfile", "Unknown PFILE")
            message_detail = payload.get("message", "")
            self._log_message(f"Server signal: Recon complete for PFILE '{pfile_processed}'. Message: '{message_detail}'")
            self.sf_client._send_message("ack_recon_complete", {"status": "received", "pfile": pfile_processed})
            self._log_message("Recon process finished. Client will now shut down.")
            return False  # Signal to stop listening loop

        elif msg_type == "error": # Server sent an error message
            self._log_message(f"Received error message from server: {payload.get('message', 'No details provided.')}", is_error=True)
            # Depending on the error, client might decide to stop.
            # For instance, if error indicates "Untrusted IP", client should stop.
            if "Untrusted IP" in payload.get('message', ''):
                return False # Stop

        else:
            self._log_message(f"Received unhandled message type from server: '{msg_type}'. Payload: {payload}", is_debug=True)

        return True # Continue listening by default

    def run(self, pfile_name_to_process: str, pfile_full_path_to_process: str, recon_options: dict | None = None):
        """
        Connects to the server and enters the main listening loop for server commands.
        """
        self.pfile_to_process_name = pfile_name_to_process
        self.pfile_to_process_full_path = pfile_full_path_to_process
        self.client_recon_options = recon_options if recon_options is not None else {}

        if not os.path.exists(self.pfile_to_process_full_path):
            self._log_message(f"Error: PFILE to process '{self.pfile_to_process_full_path}' not found. Cannot start client.", is_error=True)
            return

        self._log_message(f"Attempting to connect to server {self.server_hostname}:{self.server_port} for PFILE '{self.pfile_to_process_name}'...")
        if self.sf_client.connect():
            self._log_message(f"Successfully connected to server.")
            self._receiving_server_file_info = None # Ensure state is clean before loop

            listening = True
            while listening:
                if not self.sf_client.socket: # Check if socket was closed by a handler
                    self._log_message("Socket connection lost. Stopping listener.", is_error=True)
                    break
                
                message = self.sf_client._receive_message() # Blocking call
                if message is None:
                    self._log_message("Server disconnected or connection error. Stopping listener.", is_error=True)
                    break 
                
                try:
                    listening = self.handle_server_command(message)
                except Exception as e_handle:
                    self._log_message(f"Critical error handling server command: {e_handle}", is_error=True)
                    traceback.print_exc()
                    listening = False # Stop on unhandled exception in command handler
            
            self._log_message("Client listener loop ended.")
            self.sf_client.disconnect()
        else:
            self._log_message(f"Failed to connect to server {self.server_hostname}:{self.server_port}. Please check server status and recon.opts.", is_error=True)


if __name__ == "__main__":
    options_file_path = 'recon.opts'
    pfile_name_cli = None
    pfile_path_cli = None
    
    # Simple CLI argument parsing for PFILE path
    # For more complex CLI, consider using argparse
    import sys
    if len(sys.argv) > 1:
        if sys.argv[1] in ['-h', '--help']:
            print("Usage: python client_app.py [optional_path_to_pfile]")
            print("If no PFILE path is provided, uses CLIENT_DEFAULT_PFILE_PATH from recon.opts.")
            sys.exit(0)
        pfile_path_cli = sys.argv[1]
        pfile_name_cli = os.path.basename(pfile_path_cli)
        print(f"INFO: Using PFILE from command line argument: {pfile_path_cli}")
    
    client_app_instance = None
    try:
        # Create recon.opts with defaults if it doesn't exist.
        if not os.path.exists(options_file_path):
            print(f"INFO: Options file '{options_file_path}' not found. Attempting to create a default file.")
            try:
                readoptions(options_file_path) # This will create the default file
                print(f"INFO: Default '{options_file_path}' created. Please review and edit it, especially SHARED_KEY and paths.")
            except Exception as e_create_opts:
                print(f"ERROR: Could not create default '{options_file_path}': {e_create_opts}. Please create it manually.")
                sys.exit(1)

        client_app_instance = ReconClientApp(options_file=options_file_path)

        # Determine PFILE to use: CLI > recon.opts default
        pfile_to_use_name = pfile_name_cli if pfile_name_cli else client_app_instance.client_default_pfile_name
        pfile_to_use_path = pfile_path_cli if pfile_path_cli else client_app_instance.client_default_pfile_path
        
        # Ensure PFILE exists or create a dummy one if using the default path from config
        if not os.path.exists(pfile_to_use_path):
            # Only create dummy if the path is the one specified as default in recon.opts (or hardcoded default)
            if pfile_to_use_path == client_app_instance.client_default_pfile_path:
                print(f"INFO: Default PFILE '{pfile_to_use_path}' not found. Creating a dummy file for testing purposes.")
                try:
                    os.makedirs(os.path.dirname(pfile_to_use_path), exist_ok=True) # Ensure directory exists
                    with open(pfile_to_use_path, 'wb') as f_dummy:
                        f_dummy.write(os.urandom(10 * 1024)) # Create a 10KB dummy file
                    print(f"INFO: Created dummy PFILE at '{pfile_to_use_path}'.")
                except IOError as e_dummy:
                    print(f"ERROR: Could not create dummy PFILE at '{pfile_to_use_path}': {e_dummy}. Exiting.")
                    sys.exit(1)
            else: # If a custom path was provided via CLI and not found
                print(f"ERROR: Specified PFILE '{pfile_to_use_path}' not found. Exiting.")
                sys.exit(1)
        
        # Placeholder for client-side reconstruction options.
        # These could eventually be loaded from config or CLI as well.
        current_client_recon_options = {} 
        # Example: current_client_recon_options = {'pyscript_name': 'some_script_id_from_client'}

        client_app_instance.run(
            pfile_name_to_process=pfile_to_use_name,
            pfile_full_path_to_process=pfile_to_use_path,
            recon_options=current_client_recon_options
        )

    except FileNotFoundError as e_fnf: 
        print(f"ERROR: Initialization failed due to missing file: {e_fnf}. Ensure '{options_file_path}' exists or can be created.")
    except KeyboardInterrupt:
        print("\nINFO: Client shutting down due to KeyboardInterrupt...")
    except ConnectionRefusedError:
        # Attempt to get host/port from instance if available, otherwise use general message
        server_host = client_app_instance.server_hostname if client_app_instance else "configured host"
        server_port_val = client_app_instance.server_port if client_app_instance else "configured port"
        print(f"ERROR: Connection refused. Ensure server is running at {server_host}:{server_port_val}.")
    except Exception as e_main:
        print(f"CRITICAL ERROR: An unexpected error occurred in client application: {e_main}")
        traceback.print_exc()
    finally:
        if hasattr(client_app_instance, 'sf_client') and client_app_instance.sf_client and client_app_instance.sf_client.socket:
            print("INFO: Ensuring client is disconnected in final exception handler...")
            client_app_instance.sf_client.disconnect()
        print("INFO: Client application terminated.")

```
