# -*- coding: utf-8 -*-
"""
server_app.py: Main application for the Recon Server.

This application uses SecureFileTransferServer to handle client connections,
receive PFILES, trigger reconstruction scripts, and send results back.
"""
import os
import socket
import subprocess
import traceback
import time # For potential timeouts or delays

try:
    from reconlibs import readoptions, generate_key # generate_key might not be needed here directly
    from secure_transfer import SecureFileTransferServer, MSG_LENGTH_HEADER_SIZE
except ImportError:
    print("CRITICAL ERROR: Could not import reconlibs or secure_transfer. Ensure they are in PYTHONPATH.")
    # Attempt to provide placeholder for readoptions if missing, to allow basic structure loading
    if 'readoptions' not in globals():
        def readoptions(optionfile: str):
            print(f"Warning: Using placeholder readoptions for {optionfile}. Critical features will fail.")
            return ('localhost', 59000, 'user', 'pass', 22, '/tmp/source', '/tmp/recon_files',
                    'recon_script.sh', '/tmp/recon_dicom', '/tmp/scanner_dicom', '/tmp/server.log',
                    "dummy_shared_key_server", []) # Ensure shared_key is present
    if 'SecureFileTransferServer' not in globals():
        # This is a major issue, app cannot function
        raise ImportError("SecureFileTransferServer is missing, application cannot run.")


class ReconServerApp:
    """
    Reconstruction Server Application.
    Manages client interactions for receiving PFILEs, running reconstruction,
    and returning DICOMs.
    """
    # Default constants
    DEBUG = True # Enables more verbose output
    KEEPALIVE = True # Controls the main server loop

    def __init__(self, options_file: str = "recon.opts"):
        """
        Initializes the ReconServerApp.

        Args:
            options_file: Path to the configuration file.
        """
        self.options_file = options_file
        # Initialize attributes with default types or values before loading
        self.server_hostname: str = "localhost"
        self.server_port: int = 60000
        self.shared_key: str = ""
        self.source_data_path: str = "/tmp/dummy_source_data" # Legacy, less used
        self.recon_server_pfile_dir: str = "/tmp/recon_server_pfiles" # Server's PFILE download/work dir
        self.recon_script_path: str = "default_recon_script.sh"
        self.recon_server_dicom_output_dir: str = "/tmp/recon_server_dicoms" # Server's DICOM output dir
        self.log_filepath: str = "/tmp/recon_server.log"
        self.trusted_ips: list[str] = []
        # scanner_username, scanner_password, ssh_port, scanner_dicom_dir are read but not directly used by this app

        self._load_configuration() # Load and override defaults

        # Ensure critical paths exist
        os.makedirs(self.recon_server_pfile_dir, exist_ok=True)
        os.makedirs(self.recon_server_dicom_output_dir, exist_ok=True)

        self.sf_server = SecureFileTransferServer(
            host=self.server_hostname,
            port=self.server_port,
            shared_key=self.shared_key,
            download_dir=self.recon_server_pfile_dir # Server saves received PFILEs here
        )
        
        self._log_message(f"ReconServerApp initialized. PFILEs will be downloaded to: {self.recon_server_pfile_dir}", is_debug=False)
        if not self.shared_key or self.shared_key == "SET_YOUR_SHARED_KEY_HERE":
            self._log_message("CRITICAL WARNING: Shared key is not set or is using the default placeholder. Secure communication is compromised.", is_error=True)
            # Consider raising ValueError for operational safety if a valid key is mandatory
            # raise ValueError("A valid SHARED_KEY must be configured in recon.opts for secure operation.")

    def _log_message(self, message: str, is_error: bool = False, is_debug: bool = False, client_addr: str | None = None):
        """Helper for logging messages to console and optionally to a file."""
        prefix = ""
        if client_addr:
            prefix += f"[{client_addr}] "
        
        log_entry = f"[{time.asctime()}] {prefix}{message}"

        if is_error:
            print(f"ERROR: {log_entry}")
        elif is_debug and not self.DEBUG:
            return # Don't print debug messages if DEBUG is off
        else:
            print(log_entry)
        
        try:
            with open(self.log_filepath, 'a') as lf:
                lf.write(log_entry + "\n")
        except IOError as e:
            print(f"Warning: Could not write to log file {self.log_filepath}: {e}")


    def _load_configuration(self):
        """Loads configuration from the options file."""
        self._log_message(f"Loading configuration from '{self.options_file}'...", is_debug=True)
        try:
            (
                self.server_hostname, self.server_port,
                _scanner_username, _scanner_password, _ssh_port, # Read but unused by this app
                self.source_data_path, self.recon_server_pfile_dir, self.recon_script_path,
                self.recon_server_dicom_output_dir, _scanner_dicom_dir, self.log_filepath,
                self.shared_key, misc_options_lines
            ) = readoptions(self.options_file)

            # Parse trusted IPs from misc_options_lines
            for line in misc_options_lines:
                line_upper = line.strip().upper()
                if line_upper.startswith("#TRUSTEDIPS:"): # Handle commented out full line
                    ips_str = line.split(":", 1)[1].strip()
                    if ips_str: # Only parse if there's something after the colon
                        self.trusted_ips = [ip.strip() for ip in ips_str.split(',') if ip.strip()]
                    break # Found the TRUSTEDIPS line
                elif line_upper.startswith("TRUSTEDIPS:") and not line_upper.startswith("#"): # Handle un-commented line
                    ips_str = line.split(":", 1)[1].strip()
                    if ips_str:
                        self.trusted_ips = [ip.strip() for ip in ips_str.split(',') if ip.strip()]
                    break


            if not self.shared_key or self.shared_key == "SET_YOUR_SHARED_KEY_HERE":
                 self._log_message("SHARED_KEY is missing, empty, or using the default placeholder in recon.opts.", is_error=True)
                 # This state is already checked in __init__ for a more critical warning.

            self._log_message("Configuration loaded successfully:", is_debug=True)
            self._log_message(f"  Hostname: {self.server_hostname}, Port: {self.server_port}", is_debug=True)
            self._log_message(f"  Server PFILE Download Dir: {self.recon_server_pfile_dir}", is_debug=True)
            self._log_message(f"  Recon Script Path: {self.recon_script_path}", is_debug=True)
            self._log_message(f"  Server DICOM Output Dir: {self.recon_server_dicom_output_dir}", is_debug=True)
            self._log_message(f"  Log File: {self.log_filepath}", is_debug=True)
            self._log_message(f"  Trusted IPs: {self.trusted_ips if self.trusted_ips else 'ANY (No restrictions)'}", is_debug=True)
            self.shared_key_status = "LOADED" if self.shared_key and self.shared_key != "SET_YOUR_SHARED_KEY_HERE" else "NOT SET or PLACEHOLDER (CRITICAL!)"
            self._log_message(f"  Shared Key Status: {self.shared_key_status}", is_debug=True)

        except FileNotFoundError:
            self._log_message(f"CRITICAL: Options file '{self.options_file}' not found. Server cannot start.", is_error=True)
            raise
        except ValueError as e:
            self._log_message(f"CRITICAL: Error parsing options from '{self.options_file}'. Check data types (e.g., port number). Error: {e}", is_error=True)
            raise
        except Exception as e:
            self._log_message(f"CRITICAL: Unexpected error loading configuration from '{self.options_file}': {e}", is_error=True)
            traceback.print_exc() # Print full traceback for unexpected errors
            raise

    def _validate_ip(self, client_ip: str) -> bool:
        """
        Validates if the client's IP address is trusted.

        Args:
            client_ip: The IP address of the client.

        Returns:
            True if the IP is trusted or if no trusted IPs are configured (allowing all).
            False otherwise.
        """
        if not self.trusted_ips:
            self._log_message(f"No trusted IPs configured in '{self.options_file}'. Allowing connection from {client_ip}.", is_debug=True)
            return True
        if client_ip in self.trusted_ips:
            self._log_message(f"Client IP {client_ip} is trusted.", is_debug=True)
            return True
        self._log_message(f"Client IP {client_ip} is NOT in trusted list: {self.trusted_ips}. Denying connection.", is_error=True)
        return False

    def _trigger_external_script(self, pfile_full_path: str, client_options: dict | None = None) -> bool:
        """
        Triggers the external reconstruction script (Matlab or Python).

        Args:
            pfile_full_path: The full path to the PFILE on the server.
            client_options: Optional parameters from the client (e.g., to choose a pyscript).

        Returns:
            True if the script execution was apparently successful, False otherwise.
        """
        pfilename = os.path.basename(pfile_full_path)
        script_to_run = self.recon_script # This is the path to the script from recon.opts

        print(f"Preparing to trigger external script '{script_to_run}' for PFILE '{pfilename}'.")
        print(f"PFILE full path on server: {pfile_full_path}")
        print(f"Client options received: {client_options}")

        # Determine if it's a Python script or Matlab based on client_options or script name
        # This logic needs to be robust. For now, assume self.recon_script extension or client hint.
        is_python_script = False
        python_script_name_from_client = None

        if client_options and 'pyscript_name' in client_options:
            # If client explicitly requests a python script by name (e.g. '1', '2' from old system)
            # This implies self.recon_script might be a directory or a dispatcher.
            # For now, let's assume self.recon_script IS the python script if pyscript_name is given.
            # This part needs more clarification if self.recon_script is a Matlab script
            # and client wants to run an ALTERNATIVE python script.
            # A simple approach: if self.recon_script ends with .py, it's a python script.
            # If client sends 'pyscript_name', it might be an argument to self.recon_script (if it's a dispatcher)
            # or it implies self.recon_script should be ignored and a script from a known dict is used.
            # Let's assume 'pyscript_name' from client_options indicates the *actual* script.
            python_script_name_from_client = client_options['pyscript_name']
            # We need a way to map this name to an actual script file or assume self.recon_script is it
            if os.path.splitext(script_to_run)[1].lower() == '.py':
                 is_python_script = True
                 print(f"Identified as Python script based on extension: {script_to_run}")
            elif python_script_name_from_client:
                 # This case is tricky. If recon_script is MATLAB, but client sends pyscript_name.
                 # This means we need a predefined mapping or a convention.
                 # For now, let's assume if pyscript_name is sent, script_to_run path is ignored
                 # and we try to find python_script_name_from_client directly.
                 # This is a placeholder for a more robust mechanism.
                 # script_to_run = python_script_name_from_client # This would look for '1.py' or similar.
                 print(f"Client requested python script '{python_script_name_from_client}'. Current self.recon_script is '{script_to_run}'. This logic needs refinement.")
                 # For now, we'll stick to executing self.recon_script and see if it's Python.
                 if os.path.splitext(script_to_run)[1].lower() == '.py':
                     is_python_script = True
                 else:
                     print(f"Warning: Client sent 'pyscript_name' but main recon_script ('{script_to_run}') is not a .py file. Attempting Matlab execution.")


        elif os.path.splitext(script_to_run)[1].lower() == '.py':
            is_python_script = True
            print(f"Identified as Python script based on extension: {script_to_run}")

        command_list = []
        if is_python_script:
            # Example: python /path/to/script.py P12345.7 --some_option_from_client_if_any
            command_list = ["python", script_to_run, pfilename]
            if python_script_name_from_client and script_to_run != python_script_name_from_client:
                 # If recon_script is a general python dispatcher, it might take the specific script name as arg
                 command_list.append(f"--pyscript_target={python_script_name_from_client}")
            # Add other client options as arguments if needed
            if client_options:
                for key, value in client_options.items():
                    if key != 'pyscript_name': # Already handled or part of a different logic
                        command_list.append(f"--{key}={value}")
            print(f"Constructed Python command: {' '.join(command_list)}")

        else: # Assume Matlab
            # VARGIN needs to be the PFILE number, e.g., for P12345.7, it's 12345
            # This specific VARGIN logic was from the original script, might need adjustment
            # based on actual matlab script needs.
            try:
                # Strip 'P' and '.7' (or whatever extension)
                pfile_basename = os.path.splitext(pfilename)[0] # P12345
                vargin = pfile_basename[1:] # 12345, assuming it always starts with 'P'
                if not vargin.isdigit():
                    print(f"Warning: Could not extract numeric VARGIN from {pfilename}. Using full name.")
                    vargin = pfilename # Fallback if parsing fails
            except Exception as e:
                print(f"Error parsing PFILENAME {pfilename} for VARGIN: {e}. Using raw filename.")
                vargin = pfilename

            # Ensure recon_script path is quoted if it contains spaces, though typically not recommended.
            # The -r argument string must be carefully constructed.
            # Example: matlab -nodisplay -nojvm -r "try; run('/path/to/recon_script.m','12345'); catch e; disp(e.message); exit(1); end; exit(0);"
            matlab_command_str = f"try; run('{script_to_run}','{vargin}'); catch e; disp(e.message); exit(1); end; exit(0);"
            command_list = ["matlab", "-nodisplay", "-nojvm", "-nosplash", "-nodesktop", "-r", matlab_command_str]
            print(f"Constructed Matlab command: {' '.join(command_list)}")
        
        try:
            print(f"Executing: {' '.join(command_list)}")
            # Using subprocess.run for better control
            # CWD might matter for scripts that expect to be run from a certain directory
            # or that create output files in their CWD.
            # For now, PFILE path is absolute, output is expected in self.recon_dicom_dir.
            process = subprocess.run(command_list, capture_output=True, text=True, check=False, timeout=600) # 10 min timeout

            if process.returncode == 0:
                print(f"Script '{script_to_run}' executed successfully for {pfilename}.")
                print("Script STDOUT:")
                print(process.stdout)
                if process.stderr:
                    print("Script STDERR (though return code is 0):")
                    print(process.stderr)
                return True
            else:
                print(f"Error executing script '{script_to_run}' for {pfilename}.")
                print(f"Return Code: {process.returncode}")
                print("Script STDOUT:")
                print(process.stdout)
                print("Script STDERR:")
                print(process.stderr)
                # Log this error to self.log_file
                with open(self.log_file, 'a') as lf:
                    lf.write(f"[{time.asctime()}] Error running script {script_to_run} for {pfilename}.\n")
                    lf.write(f"Return Code: {process.returncode}\n")
                    lf.write(f"STDOUT: {process.stdout}\nSTDERR: {process.stderr}\n")
                return False
        except FileNotFoundError:
            print(f"Error: The script '{script_to_run}' or 'matlab'/'python' executable not found. Please check path and script name.")
            # Log this error
            with open(self.log_file, 'a') as lf:
                lf.write(f"[{time.asctime()}] Script or executable not found: {script_to_run}.\n")
            return False
        except subprocess.TimeoutExpired:
            print(f"Error: Script '{script_to_run}' for {pfilename} timed out.")
            with open(self.log_file, 'a') as lf:
                lf.write(f"[{time.asctime()}] Script {script_to_run} for {pfilename} timed out.\n")
            return False
        except Exception as e:
            print(f"An unexpected error occurred while trying to run the script: {e}")
            traceback.print_exc()
            with open(self.log_file, 'a') as lf:
                lf.write(f"[{time.asctime()}] Unexpected error running {script_to_run} for {pfilename}: {e}\n{traceback.format_exc()}\n")
            return False


    def run(self):
        """Main server loop to handle client connections and processing."""
        if not self.sf_server.start():
            print("Server failed to start. Exiting.")
            return

        while self.KEEPALIVE:
            print(f"\nListening for connections on {self.server_hostname}:{self.server_port}...")
            conn, addr = self.sf_server.accept_connection()

            if conn is None: # Server socket likely closed or error
                if self.KEEPALIVE: # If KEEPALIVE is true, it means error, not intentional shutdown
                    print("Error accepting connection. Server might be shutting down.")
                    time.sleep(1) # Avoid rapid spin if accept_connection fails repeatedly
                continue

            print(f"Accepted connection from: {addr}")

            if not self._validate_ip(addr[0]):
                print(f"Untrusted IP: {addr[0]}. Disconnecting client.")
                self.sf_server._send_message(conn, "error", {"message": "Untrusted IP Address."})
                conn.close()
                if conn in self.sf_server.client_connections: # Clean up from server's dict
                    del self.sf_server.client_connections[conn]
                continue
            
            # Client is connected and IP is validated. Start the recon protocol.
            try:
                # 1. Server sends "get_recon_details" to client
                print(f"[{addr[0]}] Sending 'get_recon_details' command to client.")
                if not self.sf_server.send_command_to_client(conn, "get_recon_details", {}):
                    print(f"[{addr[0]}] Failed to send 'get_recon_details' to client. Closing connection.")
                    # send_command_to_client already tries to receive an ack. If it fails, client might be unresponsive.
                    conn.close()
                    if conn in self.sf_server.client_connections: del self.sf_server.client_connections[conn]
                    continue
                
                # 2. Server receives "recon_details_response" from client
                print(f"[{addr[0]}] Waiting for 'recon_details_response' from client...")
                client_response_msg = self.sf_server._receive_message(conn)

                if not client_response_msg or client_response_msg.get("type") != "recon_details_response":
                    print(f"[{addr[0]}] Did not receive valid 'recon_details_response'. Received: {client_response_msg}. Closing.")
                    self.sf_server._send_message(conn, "error", {"message": "Invalid response to get_recon_details"})
                    conn.close()
                    if conn in self.sf_server.client_connections: del self.sf_server.client_connections[conn]
                    continue

                payload = client_response_msg.get("payload", {})
                pfile_name_on_client = payload.get("pfile_name")
                original_path_on_client = payload.get("path_on_client") # Full path on client for the pfile
                client_recon_options = payload.get("recon_options", {}) # e.g., {'pyscript_name': '1'}

                if not pfile_name_on_client or not original_path_on_client:
                    print(f"[{addr[0]}] Invalid payload in 'recon_details_response': Missing pfile_name or path_on_client. Payload: {payload}")
                    self.sf_server._send_message(conn, "error", {"message": "Missing pfile_name or path_on_client in response."})
                    conn.close()
                    if conn in self.sf_server.client_connections: del self.sf_server.client_connections[conn]
                    continue
                
                print(f"[{addr[0]}] Received recon details: PFILE='{pfile_name_on_client}', ClientPath='{original_path_on_client}', Options={client_recon_options}")

                # 3. Server requests the PFILE from the client
                print(f"[{addr[0]}] Requesting PFILE '{pfile_name_on_client}' (from client path '{original_path_on_client}').")
                # request_file_from_client just sends the message.
                # The client, upon receiving this, will use its send_file method.
                # The server now needs to be ready to receive this file.
                if not self.sf_server.request_file_from_client(conn, original_path_on_client):
                    print(f"[{addr[0]}] Failed to send 'request_file' for '{original_path_on_client}' to client. Closing.")
                    conn.close()
                    if conn in self.sf_server.client_connections: del self.sf_server.client_connections[conn]
                    continue

                # 4. Server receives the PFILE.
                # We need a way for the server to process the incoming file transfer.
                # The SecureFileTransferServer.handle_client is a loop. We can't call it directly here
                # as this `run` method is also a sort of client handling loop.
                # Solution: Add a method to SecureFileTransferServer to explicitly receive one file.
                print(f"[{addr[0]}] Waiting to receive PFILE '{pfile_name_on_client}' from client...")
                # This method will handle the file_transfer_start, file_chunk, file_transfer_end messages.
                # It will save the file to self.sf_server.download_dir (which is self.recon_filepath)
                # Pass expected_filename to ensure the client sends the correct file.
                # The actual filename saved on server might be just basename(pfile_name_on_client)
                expected_server_pfile_name = os.path.basename(pfile_name_on_client)
                received_pfile_full_path = self.sf_server.receive_file_securely(conn, expected_filename=expected_server_pfile_name)
                
                if not received_pfile_full_path:
                    print(f"[{addr[0]}] Failed to receive PFILE '{expected_server_pfile_name}' from client. Closing connection.")
                    # Error messages would have been printed by receive_file_securely or _receive_message
                    # We can send a final error to client if connection is still up.
                    # self.sf_server._send_message(conn, "error", {"message": f"Failed to receive PFILE {expected_server_pfile_name}"})
                    conn.close()
                    if conn in self.sf_server.client_connections: del self.sf_server.client_connections[conn]
                    continue
                
                print(f"[{addr[0]}] PFILE '{expected_server_pfile_name}' received successfully at '{received_pfile_full_path}'.")

                # 5. Trigger reconstruction script
                print(f"[{addr[0]}] Triggering reconstruction for '{expected_server_pfile_name}' with script '{self.recon_script}'.")
                recon_success = self._trigger_external_script(received_pfile_full_path, client_recon_options)

                if not recon_success:
                    print(f"[{addr[0]}] Reconstruction script failed for '{expected_server_pfile_name}'. Notifying client.")
                    self.sf_server.send_command_to_client(conn, "recon_status", {"status": "failed", "pfile": expected_server_pfile_name, "detail": "Reconstruction script execution failed on server."})
                    # Decide if we should still try to send any partial DICOMs or just end. For now, end.
                    conn.close()
                    if conn in self.sf_server.client_connections: del self.sf_server.client_connections[conn]
                    continue
                
                print(f"[{addr[0]}] Reconstruction script completed for '{expected_server_pfile_name}'.")

                # 6. Send reconstructed DICOMs to Client
                # DICOMs are expected to be in self.recon_dicom_dir
                # Server needs to tell client to expect files.
                print(f"[{addr[0]}] Preparing to send reconstructed DICOMs from '{self.recon_dicom_dir}'.")
                
                dicom_files_to_send = []
                if os.path.isdir(self.recon_dicom_dir):
                    dicom_files_to_send = [f for f in os.listdir(self.recon_dicom_dir) if os.path.isfile(os.path.join(self.recon_dicom_dir, f))]
                
                if not dicom_files_to_send:
                    print(f"[{addr[0]}] No DICOM files found in '{self.recon_dicom_dir}' to send for PFILE '{expected_server_pfile_name}'.")
                    # Inform client, maybe this is an error or maybe it's expected for some recons
                    self.sf_server.send_command_to_client(conn, "recon_status", {"status": "completed_no_dicoms", "pfile": expected_server_pfile_name, "message": "Reconstruction complete, but no DICOMs found to send."})
                else:
                    print(f"[{addr[0]}] Found {len(dicom_files_to_send)} DICOM file(s) to send.")
                    # Notify client it's about to receive files
                    # This protocol step could be more robust (e.g. client ack)
                    self.sf_server.send_command_to_client(conn, "dicom_transfer_start", {"num_files": len(dicom_files_to_send)})

                    for dicom_filename in dicom_files_to_send:
                        full_dicom_path_on_server = os.path.join(self.recon_dicom_dir, dicom_filename)
                        print(f"[{addr[0]}] Sending DICOM file: {dicom_filename}")
                        if not self.sf_server.send_file_to_client(conn, full_dicom_path_on_server):
                            print(f"[{addr[0]}] Failed to send DICOM file '{dicom_filename}'. Aborting further DICOM transfers for this session.")
                            # Error already logged by send_file_to_client. Client might have disconnected.
                            break # Stop sending more DICOMs
                    else: # Executed if loop completes without break
                        print(f"[{addr[0]}] All DICOM files sent successfully.")
                
                # 7. Send final "recon_complete" command
                print(f"[{addr[0]}] Sending 'recon_complete' notification to client for PFILE '{expected_server_pfile_name}'.")
                self.sf_server.send_command_to_client(conn, "recon_complete", {"pfile": expected_server_pfile_name, "message": "Reconstruction and DICOM transfer (if any) finished."})

            except socket.error as e:
                print(f"Socket error during client interaction with {addr}: {e}")
                # Log error
            except Exception as e:
                print(f"Unexpected error during client interaction with {addr}: {e}")
                traceback.print_exc()
                # Try to notify client if connection is still somewhat alive
                try:
                    self.sf_server._send_message(conn, "error", {"message": f"Unexpected server error: {str(e)}"})
                except:
                    pass # Ignore if can't send
            finally:
                print(f"[{addr[0]}] Closing connection.")
                if conn:
                    try:
                        conn.close()
                    except socket.error:
                        pass # Already closed or error
                if conn in self.sf_server.client_connections: # Ensure cleanup from server's active connection dict
                    del self.sf_server.client_connections[conn]
                print(f"Finished processing for client {addr}.")

        # End of KEEPALIVE loop
        self.sf_server.stop()
        print("ReconServerApp shut down.")


if __name__ == "__main__":
    # Ensure recon.opts exists and is correctly populated, especially with SHARED_KEY
    # Example: create a dummy recon.opts if it doesn't exist for basic testing
    # (but shared_key needs to be real for actual crypto)
    if not os.path.exists("recon.opts"):
        print("recon.opts not found, creating a dummy one for testing structure.")
        print("WARNING: The dummy recon.opts will likely NOT WORK for real operations without a valid SHARED_KEY.")
        with open("recon.opts", "w") as f:
            f.write("localhost\n") # HOSTNAME
            f.write("60000\n")     # SIGPORT
            f.write("sdc\n")       # USERNAME
            f.write("adw2.0\n")    # PASSWORD
            f.write("22\n")        # SSHPORT
            f.write("/usr/g/mrraw/\n") # MRRAW (source_data_path, for server this is less relevant if client sends all)
            f.write("/tmp/recon_server_pfiles\n") # RECON_FILEPATH (server download for PFILEs)
            f.write("matlab_recon_script.m\n") # RECONSCRIPT
            f.write("/tmp/recon_server_dicoms\n") # RECON_DICOM_DIR (server uses this to find DICOMs to send)
            f.write("/tmp/scanner_dicoms\n")   # SCANNER_DICOM_DIR (less relevant for server app)
            f.write("/tmp/recon_server.log\n") # LOGFILE
            # Generate a real key using: from cryptography.fernet import Fernet; print(Fernet.generate_key().decode())
            # And paste it here, and also in the client's recon.opts
            f.write("SHARED_KEY = your_base64_encoded_fernet_key_here\n") # SHARED_KEY
            f.write("#TRUSTEDIPS:127.0.0.1,::1\n") # Example trusted IPs
        print("Created dummy recon.opts. Please edit it with a valid SHARED_KEY and other paths.")

    app = None
    try:
        app = ReconServerApp(options_file='recon.opts')
        app.run()
    except FileNotFoundError:
        print("Could not start server: recon.opts not found or critical configuration missing.")
    except ValueError as ve: # Catch config errors from _load_configuration
        print(f"Could not start server due to configuration error: {ve}")
    except KeyboardInterrupt:
        print("\nServer shutting down due to KeyboardInterrupt...")
    except Exception as e:
        print(f"A critical error occurred: {e}")
        traceback.print_exc()
    finally:
        if hasattr(app, 'sf_server') and app.sf_server and app.sf_server.server_socket:
            print("Ensuring server is stopped in final exception handler.")
            app.sf_server.stop()
        elif hasattr(app, 'KEEPALIVE'): # If sf_server might not be init'd but app object exists
            app.KEEPALIVE = False # Attempt to stop main loop if it's running elsewhere
        print("Server application terminated.")

```
