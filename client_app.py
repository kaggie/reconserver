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

    def connect(self) -> bool:
        """Connects to the server."""
        if not self.sf_client:
            self._log_message("SecureFileTransferClient not initialized.", level="ERROR")
            return False
        if self.sf_client.is_connected():
            self._log_message("Already connected.", level="DEBUG")
            return True
        self._log_message("Connecting to server...", level="INFO")
        if self.sf_client.connect():
            self._log_message("Connection successful.", level="INFO")
            return True
        else:
            self._log_message("Connection to server failed.", level="ERROR")
            return False

    def disconnect(self):
        """Disconnects from the server."""
        if self.sf_client and self.sf_client.is_connected():
            self._log_message("Disconnecting from server...", level="INFO")
            self.sf_client.disconnect()
            self._log_message("Disconnected.", level="INFO")
        else:
            self._log_message("Not connected or client not initialized.", level="DEBUG")

    def _handle_server_message_loop(self, expected_final_command_type: str | list[str] | None = None, job_id_context: str | None = None) -> dict | None:
        """
        Internal loop to handle messages from the server until an expected command or error.
        Returns the payload of the expected final command or None on error/disconnect.
        """
        if isinstance(expected_final_command_type, str):
            expected_final_command_type = [expected_final_command_type]
        
        try:
            while True:
                server_message = self.sf_client._receive_message()
                if not server_message:
                    self._log_message("Connection lost or server ended session prematurely.", level="ERROR", job_id_context=job_id_context)
                    return None
                
                command_type = server_message.get("type")
                payload = server_message.get("payload", {})
                current_job_id = payload.get('job_id', job_id_context)


                if expected_final_command_type and command_type in expected_final_command_type:
                    self._log_message(f"Received expected final command: {command_type}", level="INFO", job_id_context=current_job_id)
                    return payload # Success, return the payload of the final command
                
                # If this message type signals the end of this interaction phase or an error
                if command_type == "error":
                    self._log_message(f"Server Error: {payload.get('message', 'Unknown server error')}", level="ERROR", job_id_context=current_job_id)
                    return None # Error state
                if command_type == "job_failed" and expected_final_command_type and "recon_complete" in expected_final_command_type : # If we were waiting for recon_complete
                    self._log_message(f"Job {current_job_id} failed: {payload.get('error')}", level="ERROR", job_id_context=current_job_id)
                    return None # Job failed, considered an error for this context

                # Process other commands that are part of an ongoing sequence but not the final one
                if not self._handle_specific_server_command(command_type, payload, job_id_context=current_job_id):
                    # _handle_specific_server_command returned False, indicating a critical issue or end of sequence
                    self._log_message(f"Terminating message loop due to handler for {command_type}.", level="WARNING", job_id_context=current_job_id)
                    return None
        except Exception as e:
            self._log_message(f"Exception in server message loop: {e}", level="ERROR", job_id_context=job_id_context)
            import traceback
            traceback.print_exc()
            return None
        return None # Should be unreachable if logic is correct

    def _handle_specific_server_command(self, command_type: str, payload: dict, job_id_context: str | None = None) -> bool:
        """
        Handles specific server commands that are part of an ongoing interaction.
        Returns False if the interaction should stop due to this command, True otherwise.
        This is a subset of the original handle_server_command, focused on non-terminal commands.
        """
        current_job_id = payload.get('job_id', job_id_context)
        self._log_message(f"Handling command: Type='{command_type}', Payload='{payload}'", level="DEBUG", job_id_context=current_job_id)

        if command_type == "get_recon_details": # Server is requesting info for a job submission
            self._log_message("Server requested recon details. Responding...", level="INFO")
            file_info_list = []
            for fp_on_client in self.files_to_process:
                file_info_list.append({"name": os.path.basename(fp_on_client), "original_path_on_client": fp_on_client})
            
            response_payload = {
                "files": file_info_list, # New key for list of files
                "client_recon_options_json": json.dumps(self.client_recon_options or {})
            }
            if not self.sf_client._send_message("recon_details_response", response_payload):
                self._log_message("Failed to send 'recon_details_response'.", level="ERROR", job_id_context=job_id_context)
                return False 
            return True 

        elif command_type == "request_file": # Server is requesting a specific file for job submission
            filepath_requested_by_server = payload.get("filepath")
            self._log_message(f"Server requested file: {filepath_requested_by_server}", level="INFO", job_id_context=job_id_context)
            # Ensure this file was one of the files intended for the current job submission context
            if filepath_requested_by_server not in self.files_to_process:
                self._log_message(f"Server requested file '{filepath_requested_by_server}' which was not part of the current job submission list. Ignoring.", level="ERROR", job_id_context=job_id_context)
                # Optionally notify server of this mismatch
                # self.sf_client._send_message("error_request_file", {"filepath": filepath_requested_by_server, "detail": "File not in current job submission list."})
                return False # Critical mismatch

            if os.path.exists(filepath_requested_by_server):
                if not self.sf_client.send_file(filepath_requested_by_server):
                    self._log_message(f"Failed to send file {filepath_requested_by_server}.", level="ERROR", job_id_context=job_id_context)
                    return False 
            else:
                self._log_message(f"File '{filepath_requested_by_server}' not found. Notifying server.", level="ERROR", job_id_context=job_id_context)
                self.sf_client._send_message("error_request_file", {"filepath": filepath_requested_by_server, "detail": "File not found on client."})
                return False 
            return True

        elif command_type == "job_queued": # Usually the end of a successful submission sequence
            self._log_message(f"Server: Job {payload.get('job_id')} queued. Files: {payload.get('num_files_received', 'N/A')}", level="INFO", job_id_context=payload.get('job_id'))
            # This is often a terminal command for submission, so the loop might exit after this.
            return True # Continue, but the calling loop should check if this is 'job_queued'

        elif command_type == "dicom_transfer_start": # Start of receiving results for a completed job
            self._log_message(f"Server starting DICOM transfer for job {payload.get('job_id')}. Expecting {payload.get('num_files')} file(s). Acknowledging.", level="INFO", job_id_context=current_job_id)
            if self.sf_client:
                 self.sf_client._send_message("ack_dicom_transfer_start", {"job_id": payload.get('job_id'), "status": "ready", "detail": "Client ready for DICOMs."})
            return True

        elif command_type in ["file_transfer_start", "file_chunk", "file_transfer_end"]: # Server sending DICOMs
            self._log_message(f"Handling server-initiated file transfer part: {command_type}", level="DEBUG", job_id_context=current_job_id)
            saved_item = self.sf_client.receive_data(save_path=self.client_download_dir) # Downloads to configured dir
            if saved_item: self._log_message(f"File operation result: {saved_item}", level="INFO", job_id_context=current_job_id)
            else: self._log_message(f"File op (type: {command_type}) failed via receive_data.", level="WARNING", job_id_context=current_job_id)
            return True 

        elif command_type == "recon_status": # Intermediate status update for a job
            self._log_message(f"Server Status (Job {payload.get('job_id')}): {payload.get('status')} - {payload.get('detail')}", level="INFO", job_id_context=payload.get('job_id'))
            return True 
            
        # Terminal commands like "recon_complete", "job_failed", "error", "server_status_response", "queue_details_response"
        # will be handled by the _handle_server_message_loop directly if they are listed as expected_final_command_type.
        # If they appear unexpectedly, the loop might terminate or log them as unknown.
        
        else:
            self._log_message(f"Unhandled or unexpected command type in _handle_specific_server_command: {command_type}", level="WARNING", job_id_context=current_job_id)
            return True # Continue by default, but this might be an issue.

    def submit_recon_job(self, files_to_process: list[str], recon_options: dict | None = None) -> str | None:
        """Submits a reconstruction job to the server and returns the Job ID."""
        if not self.sf_client or not self.sf_client.is_connected():
            self._log_message("Not connected to server. Cannot submit job.", level="ERROR")
            return None

        self.files_to_process = files_to_process # Set context for file requests
        self.client_recon_options = recon_options if recon_options else {}
        self.job_identifier_name = os.path.basename(self.files_to_process[0]) if self.files_to_process else "N/A"

        file_info_list = [{"name": os.path.basename(fp), "original_path_on_client": fp} for fp in self.files_to_process]
        
        job_submission_payload = {
            "command_name": "submit_recon_job",
            "files": file_info_list,
            "client_recon_options_json": json.dumps(self.client_recon_options)
        }
        
        self._log_message(f"Submitting job for {self.job_identifier_name} with {len(self.files_to_process)} file(s).", level="INFO")
        if not self.sf_client.send_command("submit_recon_job", job_submission_payload):
            self._log_message("Failed to send job submission command.", level="ERROR")
            return None

        # Loop to handle server messages related to this job submission (e.g., file requests)
        # Expect "job_queued" as the final successful command for this sequence.
        job_queued_payload = self._handle_server_message_loop(expected_final_command_type="job_queued")

        if job_queued_payload and job_queued_payload.get("job_id"):
            job_id = job_queued_payload["job_id"]
            self._log_message(f"Job submission successful. Job ID: {job_id}", level="INFO", job_id_context=job_id)
            return job_id
        else:
            self._log_message("Job submission failed or Job ID not received.", level="ERROR")
            return None
            
    def get_server_status(self) -> dict | None:
        """Requests server status and returns the response payload."""
        if not self.sf_client or not self.sf_client.is_connected():
            self._log_message("Not connected. Cannot get server status.", level="ERROR"); return None
        
        self._log_message("Requesting server status...", level="INFO")
        if not self.sf_client.send_command("get_server_status", {"command_name": "get_server_status"}):
            self._log_message("Failed to send get_server_status command.", level="ERROR"); return None
        
        return self._handle_server_message_loop(expected_final_command_type="server_status_response")

    def get_queue_details(self) -> dict | None:
        """Requests job queue details and returns the response payload."""
        if not self.sf_client or not self.sf_client.is_connected():
            self._log_message("Not connected. Cannot get queue details.", level="ERROR"); return None

        self._log_message("Requesting queue details...", level="INFO")
        if not self.sf_client.send_command("get_queue_details", {"command_name": "get_queue_details"}):
            self._log_message("Failed to send get_queue_details command.", level="ERROR"); return None

        return self._handle_server_message_loop(expected_final_command_type="queue_details_response")

    def process_job_and_get_results(self, job_id: str) -> bool:
        """
        After a job is queued, this method listens for messages related to that job
        (status, DICOM transfer, completion/failure).
        """
        if not self.sf_client or not self.sf_client.is_connected():
            self._log_message(f"Not connected. Cannot process results for job {job_id}.", level="ERROR", job_id_context=job_id)
            return False
        
        self._log_message(f"Waiting for results/completion of job {job_id}...", level="INFO", job_id_context=job_id)
        
        # Listen for "recon_complete" or "job_failed"
        final_payload = self._handle_server_message_loop(
            expected_final_command_type=["recon_complete", "job_failed"],
            job_id_context=job_id
        )

        if final_payload:
            if final_payload.get("job_id") == job_id and final_payload.get("type") == "recon_complete": # Check type if it's added to payload by wrapper
                 self._log_message(f"Job {job_id} completed successfully and results processed.", level="INFO", job_id_context=job_id)
                 return True
            elif final_payload.get("job_id") == job_id: # Could be job_failed
                 self._log_message(f"Job {job_id} processing finished (may have failed or no specific 'recon_complete' type). Payload: {final_payload}", level="INFO", job_id_context=job_id)
                 # Check if it was actually job_failed
                 server_message = self.sf_client.last_received_message # Hacky, improve this
                 if server_message and server_message.get("type") == "job_failed":
                     return False
                 return True # Assume complete if not explicitly failed here
        
        self._log_message(f"Failed to get completion for job {job_id} or error occurred.", level="ERROR", job_id_context=job_id)
        return False

    # Simplified run for CLI, can be adapted or CLI can call specific methods.
    def run_full_job_cycle(self, files_to_process: list[str], recon_options: dict | None = None):
        """Connects, submits a job, waits for results, and disconnects."""
        if not self.connect():
            return False
        
        job_id = None
        success = False
        try:
            job_id = self.submit_recon_job(files_to_process, recon_options)
            if job_id:
                success = self.process_job_and_get_results(job_id)
            else:
                self._log_message("Failed to submit job, cannot process results.", level="ERROR")
        except Exception as e:
            self._log_message(f"An error occurred during client execution: {e}", level="ERROR", job_id_context=job_id)
            import traceback
            traceback.print_exc()
            success = False
        finally:
            self.disconnect()
            self._log_message(f"Client session for job {job_id if job_id else 'N/A'} finished. Success: {success}", is_debug=False)
        return success


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Recon Client Application.")
    parser.add_argument("--files", nargs='+', help="One or more full paths to PFILEs to process for a full job cycle.")
    parser.add_argument("--directory", help="Directory containing PFILEs to process for a full job cycle.")
    parser.add_argument("--pattern", default="P*.7", help="Filename pattern to use with --directory (e.g., 'P*.7', '*.dcm'). Default: P*.7")
    parser.add_argument("--opts", default="recon.opts", help="Path to the options file (default: recon.opts)")
    parser.add_argument("--recon-script-name", help="Specify a particular Python recon script registered on server (e.g., 'slicerecon') for job submission.")
    parser.add_argument("--target-slices", type=int, help="Example option: target number of slices for recon for job submission.")
    # New CLI arguments for specific actions
    parser.add_argument("--server-status", action="store_true", help="Get server status.")
    parser.add_argument("--view-queue", action="store_true", help="View current job queue on the server.")

    args = parser.parse_args()

    client_options = {}
    if args.recon_script_name:
        client_options["pyscript_name"] = args.recon_script_name
    if args.target_slices is not None:
        client_options["num_slices"] = args.target_slices

    app = None
    try:
        app = ReconClientApp(options_file=args.opts)

        if args.server_status:
            if app.connect():
                status = app.get_server_status()
                if status:
                    print("\n--- Server Status ---")
                    for key, value in status.items():
                        print(f"{key.replace('_', ' ').title()}: {value}")
                    print("---------------------\n")
                else:
                    print("Failed to retrieve server status.")
                app.disconnect()
        elif args.view_queue:
            if app.connect():
                queue_data = app.get_queue_details()
                if queue_data and "jobs" in queue_data:
                    print("\n--- Job Queue ---")
                    if queue_data["jobs"]:
                        for job in queue_data["jobs"]:
                            print(f"  Job ID: {job.get('job_id')}")
                            print(f"    Status: {job.get('status')}")
                            print(f"    Primary File: {job.get('primary_input_file_name')}")
                            print(f"    Num Files: {job.get('num_input_files')}")
                            print(f"    Submitted: {job.get('submitted_at_utc')}")
                            print(f"    Server Dir Basename: {job.get('job_input_dir_basename')}")
                            print("-" * 15)
                    else:
                        print("Queue is empty.")
                    print(f"Total jobs in queue: {queue_data.get('count', 0)}")
                    print("-----------------\n")
                else:
                    print("Failed to retrieve job queue details.")
                app.disconnect()
        elif args.files or args.directory:
            files_to_send_list = []
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
            
            if not files_to_send_list:
                 app._log_message("No files selected for processing. Exiting.", level="ERROR")
                 sys.exit(1)
            app.run_full_job_cycle(files_to_process=files_to_send_list, recon_options=client_options)
        else:
            # Default behavior: if no specific action and no files, show help.
            # Or, could run default PFILE if configured and exists. For now, require explicit action.
            parser.print_help()
            # Example: run default PFILE as a full cycle
            # if os.path.exists(app.default_pfile_path):
            #     app._log_message(f"No specific action, running default PFILE: {app.default_pfile_path}", level="INFO")
            #     app.run_full_job_cycle(files_to_process=[app.default_pfile_path], recon_options=client_options)
            # else:
            #     print("\nNo input files specified for job cycle, and default PFILE not found.")


    except FileNotFoundError: # From readoptions, if it fails to create/read
        print(f"ERROR: Options file '{args.opts}' not found or could not be processed.")
    except Exception as e:
        print(f"CLIENT MAIN ERROR: An unexpected error occurred: {e}")
        import traceback
        traceback.print_exc()
    finally:
        # Disconnect is handled by individual methods or run_full_job_cycle now
        if app and app.sf_client and app.sf_client.is_connected() and not (args.server_status or args.view_queue or args.files or args.directory) :
             # If no specific action was run that handles its own disconnect
             app.disconnect()
        print("Client application terminated.")
