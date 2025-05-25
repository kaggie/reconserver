# -*- coding: utf-8 -*-
"""
client_app.py: Main application for the Recon Client.

This application uses SecureFileTransferClient to connect to the server,
send PFILE details (potentially for multiple files), transfer the files, 
and then listen for job status and results (DICOM files).
"""
import os
import argparse
import json
import time
import sys
import glob

try:
    from reconlibs import readoptions
    from secure_transfer import SecureFileTransferClient
except ImportError as e:
    print(f"CRITICAL ERROR: Could not import necessary modules: {e}. Ensure reconlibs.py and secure_transfer.py are in PYTHONPATH.")
    if 'readoptions' not in globals():
        def readoptions(optionfile: str): # type: ignore
            print(f"Warning: Using placeholder readoptions for {optionfile}.")
            return ('localhost', 60000, 'user', 'pass', 22, '/tmp/source', 
                    '/tmp/recon_server_pfiles', 'default_recon_script.sh', 
                    '/tmp/recon_server_dicoms', '/tmp/scanner_dicom', 
                    '/tmp/recon_client.log', "SET_YOUR_SHARED_KEY_HERE", 1, []) 
    if 'SecureFileTransferClient' not in globals(): # type: ignore
        sys.exit(1)


class ReconClientApp:
    """
    Reconstruction Client Application.
    Handles connection to the server, PFILE transfer, and result reception.
    """
    DEBUG = True

    def __init__(self, options_file: str = "recon.opts"):
        self.options_file = options_file
        self.server_hostname: str = "localhost"
        self.server_port: int = 60000
        self.shared_key: str = ""
        self.client_download_dir: str = "client_downloads" 
        self.default_pfile_name: str = "P00000.7" 
        self.default_pfile_path: str = "/tmp/default_pfile_on_client/P00000.7"
        self.log_filepath: str = "/tmp/recon_client.log"

        self.files_to_process: list[str] = [] # List of full paths of files to send
        self.job_identifier_name: str = "N/A" # For logging, often basename of first file
        self.client_recon_options: dict = {}

        self._load_configuration()
        os.makedirs(self.client_download_dir, exist_ok=True)
        
        self.sf_client = SecureFileTransferClient(
            host=self.server_hostname,
            port=self.server_port,
            shared_key=self.shared_key
        )
        self._log_message("ReconClientApp initialized.", is_debug=False)
        if not self.shared_key or self.shared_key == "SET_YOUR_SHARED_KEY_HERE":
            self._log_message("CRITICAL WARNING: Shared key is not set or placeholder. Communication is insecure.", is_error=True)

    def _log_message(self, message: str, level: str = "INFO", is_error:bool=False, is_debug:bool=False):
        if is_error and level == "INFO": level = "ERROR"
        if is_debug and level == "INFO": level = "DEBUG"
        if level == "DEBUG" and not self.DEBUG: return

        log_entry = f"[{time.asctime()}] [ClientApp] [{level}] {message}"
        print(log_entry)
        try:
            with open(self.log_filepath, 'a') as lf: lf.write(log_entry + "\n")
        except IOError as e: print(f"Warning: Could not write to log file {self.log_filepath}: {e}")

    def _load_configuration(self):
        self._log_message(f"Loading configuration from '{self.options_file}'...", level="DEBUG")
        try:
            config_dict = readoptions(self.options_file)

            self.server_hostname = config_dict.get('SERVER_HOSTNAME', 'localhost')
            # Ensure server_port is an int, readoptions should handle this, but good to be defensive or ensure it.
            port_val = config_dict.get('SERVER_PORT', 60000)
            try:
                self.server_port = int(port_val)
            except ValueError:
                self._log_message(f"Invalid SERVER_PORT value '{port_val}'. Using default 60000.", level="WARNING")
                self.server_port = 60000
            
            self.log_filepath = config_dict.get('LOG_FILEPATH', '/tmp/recon_client.log')
            self.shared_key = config_dict.get('SHARED_KEY', 'SET_YOUR_SHARED_KEY_HERE')
            self.client_download_dir = config_dict.get('CLIENT_DOWNLOAD_DIR', 'client_downloads')
            self.default_pfile_name = config_dict.get('CLIENT_DEFAULT_PFILE_NAME', 'P00000.7')
            self.default_pfile_path = config_dict.get('CLIENT_DEFAULT_PFILE_PATH', '/tmp/default_pfile_on_client/P00000.7')

            # Legacy options that might be in old files but are not primary settings for client_app itself
            # These are mostly for info or if other parts of a larger system might use them from the same opts file.
            # No need to assign them to self unless client_app directly uses them.
            # For example, SCANNER_USERNAME, SCANNER_PASSWORD, etc. are not used by ReconClientApp.

            self._log_message(f"Config loaded: Server Host={self.server_hostname}, Port={self.server_port}, "
                              f"Log File={self.log_filepath}, Shared Key "
                              f"{'SET' if self.shared_key != 'SET_YOUR_SHARED_KEY_HERE' else 'NOT SET (Using Placeholder)'}, "
                              f"Download Dir={self.client_download_dir}", level="DEBUG")

        except FileNotFoundError:
            # This case should ideally be handled by readoptions creating a default file.
            # If it still occurs, it means readoptions might have failed to create or access it.
            self._log_message(f"CRITICAL: Options file '{self.options_file}' not found and could not be created/read by readoptions. Client cannot start.", level="ERROR")
            raise
        except KeyError as e:
            # This might occur if readoptions returns a dict missing an absolutely essential key that doesn't have a .get() default.
            self._log_message(f"CRITICAL: Missing essential configuration key '{e}' in '{self.options_file}'. Client cannot start.", level="ERROR")
            raise
        except Exception as e:
            # Catch any other unexpected errors from readoptions or during assignment
            self._log_message(f"CRITICAL: Unexpected error loading configuration from '{self.options_file}': {e}", level="ERROR")
            import traceback # Keep traceback import here for this specific exception logging.
            traceback.print_exc()
            raise

    def handle_server_command(self, command_type: str, payload: dict) -> bool:
        self._log_message(f"Received command: Type='{command_type}', Payload='{payload}'", level="DEBUG")

        if command_type == "get_recon_details": # Server is requesting info
            self._log_message("Server requested recon details. Responding...", level="INFO")
            file_info_list = []
            for fp_on_client in self.files_to_process:
                file_info_list.append({"name": os.path.basename(fp_on_client), "original_path_on_client": fp_on_client})
            
            response_payload = {
                "files": file_info_list, # New key for list of files
                "client_recon_options_json": json.dumps(self.client_recon_options or {})
            }
            if not self.sf_client._send_message("recon_details_response", response_payload):
                self._log_message("Failed to send 'recon_details_response'.", level="ERROR")
                return False # Stop
            return True # Continue

        elif command_type == "request_file": # Server is requesting a specific file
            filepath_requested_by_server = payload.get("filepath")
            self._log_message(f"Server requested file: {filepath_requested_by_server}", level="INFO")
            if filepath_requested_by_server and os.path.exists(filepath_requested_by_server):
                if not self.sf_client.send_file(filepath_requested_by_server):
                    self._log_message(f"Failed to send file {filepath_requested_by_server}.", level="ERROR")
                    return False # Stop on send failure
            else:
                self._log_message(f"File '{filepath_requested_by_server}' not found or invalid request. Notifying server.", level="ERROR")
                self.sf_client._send_message("error_request_file", {"filepath": filepath_requested_by_server, "detail": "File not found on client or invalid request."})
                return False # Stop
            return True

        elif command_type == "job_queued":
            self._log_message(f"Server: {payload.get('message')} (Job ID: {payload.get('job_id')}, Files: {payload.get('num_files_received', payload.get('filename'))})")
            return True 

        elif command_type == "job_failed":
            self._log_message(f"Server: Job {payload.get('job_id')} for {payload.get('pfile', self.job_identifier_name)} failed. Error: {payload.get('error')}", level="ERROR")
            return False 

        elif command_type == "dicom_transfer_start":
            self._log_message(f"Server starting DICOM transfer for job {payload.get('job_id')}. Expecting {payload.get('num_files')} file(s). Acknowledging.", level="INFO")
            if self.sf_client:
                 self.sf_client._send_message("ack_dicom_transfer_start", {"job_id": payload.get('job_id'), "status": "ready", "detail": "Client ready for DICOMs."})
            return True

        elif command_type in ["file_transfer_start", "file_chunk", "file_transfer_end"]: # Server sending DICOMs
            self._log_message(f"Handling server-initiated file transfer part: {command_type}", level="DEBUG")
            saved_item = self.sf_client.receive_data(save_path=self.client_download_dir)
            if saved_item: self._log_message(f"File operation result: {saved_item}", level="INFO")
            else: self._log_message(f"File op (type: {command_type}) failed via receive_data.", level="WARNING")
            return True 

        elif command_type == "recon_status":
            self._log_message(f"Server Status (Job {payload.get('job_id')}, PFILE {payload.get('pfile')}): {payload.get('status')} - {payload.get('detail')}", level="INFO")
            return True 

        elif command_type == "recon_complete":
            self._log_message(f"Server: Recon complete for {payload.get('pfile', self.job_identifier_name)} (Job ID: {payload.get('job_id')}). Msg: {payload.get('message')}", level="INFO")
            return False 

        elif command_type == "error":
            self._log_message(f"Server Error: {payload.get('message', 'Unknown server error')}", level="ERROR")
            return False 
            
        else:
            self._log_message(f"Unknown command type: {command_type}", level="WARNING")
            return True

    def run(self, files_to_process: list[str], recon_options: dict | None = None):
        self.files_to_process = files_to_process
        self.client_recon_options = recon_options if recon_options else {}
        if self.files_to_process:
            self.job_identifier_name = os.path.basename(self.files_to_process[0])
        else:
            self._log_message("No files provided to process.", level="ERROR")
            return False

        if not self.sf_client.connect():
            self._log_message("Connection to server failed.", level="ERROR")
            return False

        try:
            self._log_message("Listening for server commands...", level="INFO")
            while True: # Main loop to handle server messages
                server_message = self.sf_client._receive_message()
                if not server_message:
                    self._log_message("Connection lost or server ended session.", level="ERROR")
                    break 
                
                command_type = server_message.get("type")
                payload = server_message.get("payload", {})

                if not self.handle_server_command(command_type, payload):
                    break # handle_server_command returned False, signal to stop
            return True
        except Exception as e:
            self._log_message(f"An error occurred during client execution: {e}", level="ERROR")
            traceback.print_exc()
            return False
        finally:
            self.sf_client.disconnect()
            self._log_message("Client session finished.", is_debug=False)


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Recon Client Application.")
    parser.add_argument("--files", nargs='+', help="One or more full paths to PFILEs to process.")
    parser.add_argument("--directory", help="Directory containing PFILEs to process.")
    parser.add_argument("--pattern", default="P*.7", help="Filename pattern to use with --directory (e.g., 'P*.7', '*.dcm'). Default: P*.7")
    parser.add_argument("--opts", default="recon.opts", help="Path to the options file (default: recon.opts)")
    parser.add_argument("--recon-script-name", help="Specify a particular Python recon script registered on server (e.g., 'slicerecon')")
    parser.add_argument("--target-slices", type=int, help="Example option: target number of slices for recon.")

    args = parser.parse_args()

    client_options = {}
    if args.recon_script_name:
        client_options["pyscript_name"] = args.recon_script_name 
    if args.target_slices is not None:
        client_options["num_slices"] = args.target_slices
    
    app = None
    files_to_send_list = []

    try:
        app = ReconClientApp(options_file=args.opts) # Load config first

        if args.directory:
            if not os.path.isdir(args.directory):
                print(f"ERROR: Provided directory does not exist: {args.directory}")
                sys.exit(1)
            search_pattern = os.path.join(args.directory, args.pattern)
            files_to_send_list = glob.glob(search_pattern)
            if not files_to_send_list:
                print(f"No files found in directory {args.directory} matching pattern {args.pattern}")
                sys.exit(1)
            app._log_message(f"Found {len(files_to_send_list)} files in directory {args.directory} matching {args.pattern}.", level="INFO")
        elif args.files:
            files_to_send_list = args.files
            for f_path in files_to_send_list:
                if not os.path.exists(f_path):
                    print(f"ERROR: File not found: {f_path}")
                    sys.exit(1)
            app._log_message(f"Processing {len(files_to_send_list)} files specified on command line.", level="INFO")
        else:
            # Fallback to default PFILE from config if no other input given
            if os.path.exists(app.default_pfile_path):
                app._log_message(f"No files/directory specified, using default PFILE: {app.default_pfile_path}", level="INFO")
                files_to_send_list = [app.default_pfile_path]
            else:
                parser.print_help()
                print("\nERROR: No input files specified via --files or --directory, and default PFILE not found.")
                sys.exit(1)
        
        if not files_to_send_list: # Should be caught above, but as a safeguard
             app._log_message("No files selected for processing. Exiting.", level="ERROR")
             sys.exit(1)

        app.run(files_to_process=files_to_send_list, recon_options=client_options)

    except FileNotFoundError:
        print(f"ERROR: Options file '{args.opts}' not found.")
    except Exception as e:
        print(f"CLIENT MAIN ERROR: An unexpected error occurred: {e}")
        traceback.print_exc()
    finally:
        if app and app.sf_client and app.sf_client.socket:
            app.sf_client.disconnect()
        print("Client application terminated.")

```
