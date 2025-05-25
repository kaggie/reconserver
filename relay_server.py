import logging
import os
import sys
import time
import threading
import socket
import json
import uuid # For generating relay_job_id
import shutil # For cleaning up temp directories
from pythonjsonlogger import jsonlogger 

try:
    from reconlibs import readoptions, generate_key
    from secure_transfer import SecureFileTransferServer, SecureFileTransferClient
except ImportError:
    print(json.dumps({
        "timestamp": time.strftime('%Y-%m-%dT%H:%M:%S%z'), "level": "CRITICAL", "name": __name__, 
        "message": f"Could not import necessary modules. Ensure reconlibs.py and secure_transfer.py are in PYTHONPATH."
    }))
    sys.exit(1)

RELAY_CONFIG = {}
logger = logging.getLogger(__name__) 
logger.addHandler(logging.NullHandler()) 

def setup_logging():
    global logger 
    
    log_level_str = RELAY_CONFIG.get('LOG_LEVEL', 'INFO').upper()
    log_level = getattr(logging, log_level_str, logging.INFO)
    log_filepath = RELAY_CONFIG.get('LOG_FILEPATH', '/tmp/relay_server.log')

    logger = logging.getLogger("RelayServerApp")
    logger.setLevel(log_level)
    logger.propagate = False 

    for handler in logger.handlers[:]:
        logger.removeHandler(handler)

    formatter = jsonlogger.JsonFormatter(
        '%(asctime)s %(levelname)s %(name)s %(threadName)s %(module)s %(funcName)s %(lineno)d %(message)s',
        timestamp=True
    )

    stream_handler = logging.StreamHandler(sys.stdout)
    stream_handler.setFormatter(formatter)
    stream_handler.setLevel(log_level)
    logger.addHandler(stream_handler)

    if log_filepath:
        try:
            log_dir = os.path.dirname(log_filepath)
            if log_dir and not os.path.exists(log_dir):
                os.makedirs(log_dir, exist_ok=True)
            
            file_handler = logging.FileHandler(log_filepath, mode='a')
            file_handler.setFormatter(formatter)
            file_handler.setLevel(log_level)
            logger.addHandler(file_handler)
            logger.info("Logging configured to console and file.", extra={'log_filepath': log_filepath, 'log_level': log_level_str})
        except Exception as e:
            logger.error("Failed to set up file logging.", exc_info=True, extra={'log_filepath': log_filepath, 'error_details': str(e)})
            logger.info("Logging configured to console only.", extra={'log_level': log_level_str})
    else:
        logger.info("Logging configured to console only (no log_filepath specified).", extra={'log_level': log_level_str})


class RelayServerApp:
    def __init__(self, config_dict):
        self.config = config_dict
        self.logger = logging.getLogger(f"{__name__}.{self.__class__.__name__}")
        
        self.sf_server = None # For client-to-relay connections
        self.shutdown_event = threading.Event()
        self.health_check_thread = None
        self.backend_servers_list = [] 
        self.current_backend_index = 0 
        self.start_time = time.time()

        self.admin_sf_server = None
        self.admin_listener_thread = None
        self.relay_admin_port = 60002 
        self.relay_admin_shared_key = "" 
        
        self.active_client_connections = {} 
        self.client_handling_threads = [] 
        self.admin_handling_threads = []

        # New attributes for relay functionality
        self.shared_key_for_backends = ""
        self.relay_job_temp_dir = "/tmp/relay_job_files"
        self.active_relayed_jobs = {} # relay_job_id -> {original_client_conn_details, backend_sft_client, backend_job_id, relay_temp_job_dir, original_client_files}
        self.job_tracking_lock = threading.Lock() # To protect access to active_relayed_jobs

        self._load_config() 

    def _load_config(self):
        self.logger.debug("Loading relay server configurations.")
        self.relay_admin_port = int(self.config.get('RELAY_ADMIN_PORT', 60002))
        self.relay_admin_shared_key = self.config.get('RELAY_ADMIN_SHARED_KEY', '')
        
        admin_key_status = 'set'
        if not self.relay_admin_shared_key or self.relay_admin_shared_key == 'SET_YOUR_RELAY_ADMIN_KEY_HERE':
            self.logger.critical("RELAY_ADMIN_SHARED_KEY is not set or placeholder. Admin interface will NOT start.", extra={'security_issue': 'invalid_admin_key'})
            self.relay_admin_shared_key = "" 
            admin_key_status = 'not_set_or_placeholder'
        
        self.shared_key_for_backends = self.config.get('SHARED_KEY_FOR_BACKENDS', '')
        backend_key_status = 'set'
        if not self.shared_key_for_backends or self.shared_key_for_backends == 'SET_YOUR_BACKEND_SERVERS_SHARED_KEY_HERE':
            self.logger.critical("SHARED_KEY_FOR_BACKENDS is not set or placeholder. Relay cannot connect to backends.", extra={'security_issue': 'invalid_backend_key'})
            self.shared_key_for_backends = "" # Prevent attempts if not set
            backend_key_status = 'not_set_or_placeholder'

        self.relay_job_temp_dir = self.config.get('RELAY_JOB_TEMP_DIR', '/tmp/relay_job_files')
        try:
            os.makedirs(self.relay_job_temp_dir, exist_ok=True)
        except OSError as e:
            self.logger.critical(f"Failed to create relay job temp directory.", exc_info=True, extra={'path': self.relay_job_temp_dir, 'error_details': str(e)})
            return False # Critical failure

        self.logger.info("Relay configurations loaded.", extra={
            'admin_port': self.relay_admin_port, 'admin_key_status': admin_key_status,
            'backend_key_status': backend_key_status, 'relay_job_temp_dir': self.relay_job_temp_dir
        })
        
        if not self._parse_backend_servers():
             self.logger.critical("Failed to parse backend server configuration.")
             return False
        return True

    def _parse_backend_servers(self):
        # ... (no changes from previous version, already logs appropriately)
        backend_servers_str = self.config.get('BACKEND_SERVERS', '')
        log_ctx = {'backend_servers_config_str': backend_servers_str}
        if not backend_servers_str:
            self.logger.error("No backend servers configured (BACKEND_SERVERS is empty). Relay cannot function.", extra=log_ctx)
            return False
        
        servers = []
        for s_entry in backend_servers_str.split(','):
            s_entry = s_entry.strip()
            if not s_entry: continue
            try:
                host, port_str = s_entry.split(':')
                port = int(port_str)
                # Initialize client as None, it will be created on demand
                servers.append({'host': host, 'port': port, 'sft_client_to_backend': None, 'healthy': False, 'name': s_entry})
            except ValueError:
                self.logger.error(f"Invalid backend server entry format. Expected host:port.", extra={**log_ctx, 'invalid_entry': s_entry})
        
        if not servers:
            self.logger.error("No valid backend servers found after parsing BACKEND_SERVERS.", extra=log_ctx)
            return False
            
        self.backend_servers_list = servers
        self.logger.info(f"Parsed backend servers.", extra={**log_ctx, 'parsed_backend_names': [s['name'] for s in self.backend_servers_list]})
        return True


    def start(self):
        # ... (initial logging and main sf_server startup is mostly the same)
        self.logger.info("Starting Relay Server application...")
        # _load_config was already called from __init__ in this version, but if it can fail, check here
        # For this task, assume _load_config in __init__ is sufficient or start sequence is adjusted.

        relay_hostname = self.config.get('RELAY_HOSTNAME', 'localhost')
        relay_port = int(self.config.get('RELAY_PORT', 60001))
        shared_key_clients = self.config.get('SHARED_KEY_RELAY_TO_CLIENTS', '')
        
        start_ctx = {'relay_hostname': relay_hostname, 'relay_port': relay_port}
        if shared_key_clients == 'SET_YOUR_RELAY_TO_CLIENTS_KEY_HERE' or not shared_key_clients:
            self.logger.critical("SHARED_KEY_RELAY_TO_CLIENTS is not set or placeholder. Cannot start securely.", extra={**start_ctx, 'security_issue': 'invalid_main_relay_key'})
            return False
        if not self.shared_key_for_backends: # Check if backend key is loaded
            self.logger.critical("SHARED_KEY_FOR_BACKENDS is not configured. Relay cannot forward jobs to backends.", extra=start_ctx)
            return False


        self.sf_server = SecureFileTransferServer(
            host=relay_hostname, port=relay_port, shared_key=shared_key_clients,
            download_dir=None, # Relay handles downloads into its own temp job dirs
            logger=self.logger.getChild("SFTServer.MainRelayPort")
        )
        
        if not self.sf_server.start():
            self.logger.error("Main SecureFileTransferServer for client connections failed to start.", extra=start_ctx)
            return False
        self.logger.info("Relay server listening for clients.", extra=start_ctx)

        if self.relay_admin_shared_key: # Admin interface startup
            self.admin_sf_server = SecureFileTransferServer(
                host=relay_hostname, port=self.relay_admin_port, shared_key=self.relay_admin_shared_key,
                download_dir=None, logger=self.logger.getChild("SFTServer.AdminRelayPort")
            )
            if not self.admin_sf_server.start():
                self.logger.error("Relay admin interface failed to start.", extra={'admin_port': self.relay_admin_port})
                self.admin_sf_server = None
            else:
                self.logger.info("Relay admin interface listening.", extra={'admin_host': relay_hostname, 'admin_port': self.relay_admin_port})
                self.admin_listener_thread = threading.Thread(target=self._admin_listener_loop, name="AdminListenerThread", daemon=True)
                self.admin_listener_thread.start()
        else:
            self.logger.warning("Admin interface shared key not configured. Admin interface will not be available.")

        self.health_check_thread = threading.Thread(target=self._health_check_loop, name="HealthCheckThread", daemon=True)
        self.health_check_thread.start()

        try:
            while not self.shutdown_event.is_set():
                conn, addr = self.sf_server.accept_connection()
                if conn:
                    log_ctx_conn = {'client_ip': addr[0], 'client_port': addr[1], 'thread_name': threading.current_thread().name}
                    self.logger.info("Accepted new client connection.", extra=log_ctx_conn)
                    # Note: active_client_connections tracking moved inside handle_client_connection
                    client_thread = threading.Thread(target=self.handle_client_connection, args=(conn, addr, log_ctx_conn), name=f"ClientRelay-{addr[0]}-{addr[1]}", daemon=True)
                    self.client_handling_threads.append(client_thread)
                    client_thread.start()
                elif self.shutdown_event.is_set(): break 
        except Exception as e:
            if not self.shutdown_event.is_set():
                 self.logger.critical("Error in main client accept loop.", exc_info=True)
        
        self.logger.info("Relay Server main client accept loop ended.")
        return True 

    # ... (admin listener, stop, health check, status methods remain largely the same but use new logger) ...
    # Minor logging updates in existing methods:
    def _admin_listener_loop(self):
        log_ctx_loop = {'thread_name': threading.current_thread().name}
        self.logger.info("Admin listener loop started.", extra=log_ctx_loop)
        try:
            while not self.shutdown_event.is_set():
                if not self.admin_sf_server: 
                    self.logger.critical("Admin server not initialized in admin listener loop.", extra=log_ctx_loop)
                    break
                conn, addr = self.admin_sf_server.accept_connection()
                if conn:
                    log_ctx_admin_conn = {'admin_client_ip': addr[0], 'admin_client_port': addr[1], **log_ctx_loop}
                    self.logger.info("Accepted admin connection.", extra=log_ctx_admin_conn)
                    admin_client_thread = threading.Thread(target=self.handle_admin_command, args=(conn, addr, log_ctx_admin_conn), name=f"AdminClient-{addr[0]}-{addr[1]}", daemon=True)
                    self.admin_handling_threads.append(admin_client_thread)
                    admin_client_thread.start()
                elif self.shutdown_event.is_set(): break
        except Exception as e:
            if not self.shutdown_event.is_set():
                self.logger.critical("Error in admin accept loop.", exc_info=True, extra=log_ctx_loop)
        self.logger.info("Admin listener loop ended.", extra=log_ctx_loop)

    def stop(self):
        self.logger.info("Stopping Relay Server...")
        self.shutdown_event.set() 
        if self.sf_server: self.sf_server.stop()
        if self.admin_sf_server: self.admin_sf_server.stop()
        
        threads_to_join = []
        if self.health_check_thread and self.health_check_thread.is_alive(): threads_to_join.append(self.health_check_thread)
        if self.admin_listener_thread and self.admin_listener_thread.is_alive(): threads_to_join.append(self.admin_listener_thread)
        
        # Include active job relay threads if any were stored and need joining
        with self.job_tracking_lock: # Protect access to active_relayed_jobs if threads are removed from it
            for job_id, job_info in self.active_relayed_jobs.items():
                if job_info.get('thread') and job_info['thread'].is_alive():
                    threads_to_join.append(job_info['thread'])
        
        # Join client and admin handler threads (these might be numerous)
        # For simplicity, we're only joining the main listener threads and specific job threads.
        # A more robust shutdown might involve iterating self.client_handling_threads etc.
        # but they are daemonized, so they will exit if main exits after sf_server.stop() unblocks accept.

        for t in threads_to_join:
            try:
                t.join(timeout=1.0) 
            except Exception as e:
                self.logger.error(f"Error joining thread {t.name}.", exc_info=True, extra={'thread_name': t.name})
        
        self.logger.info("Relay Server stopped.")


    def _health_check_loop(self):
        health_check_interval = int(self.config.get('HEALTH_CHECK_INTERVAL', 30))
        log_ctx = {'health_check_interval': health_check_interval, 'thread_name': threading.current_thread().name}
        self.logger.info("Health check loop started.", extra=log_ctx)
        while not self.shutdown_event.wait(health_check_interval):
            self.perform_health_checks()
        self.logger.info("Health check loop stopped.", extra=log_ctx)


    def handle_client_connection(self, client_conn, client_addr_tuple, log_ctx_conn):
        relay_job_id = str(uuid.uuid4())
        log_ctx = {**log_ctx_conn, 'relay_job_id': relay_job_id}
        self.logger.info("Handling new client connection for potential job relay.", extra=log_ctx)
        
        # Add to active connections for admin CLI
        self.active_client_connections[client_addr_tuple] = {'connect_time': time.time(), 'ip': client_addr_tuple[0], 'port': client_addr_tuple[1], 'relay_job_id': relay_job_id}

        # Create job-specific temporary directory on the relay
        current_relay_job_temp_dir = os.path.join(self.relay_job_temp_dir, f"relay_job_{relay_job_id}")
        backend_sft_client = None # Initialize
        job_successfully_relayed_to_backend = False

        try:
            os.makedirs(current_relay_job_temp_dir, exist_ok=True)
            log_ctx['relay_temp_job_dir'] = current_relay_job_temp_dir
            self.logger.info("Created temporary directory for relay job.", extra=log_ctx)

            if not self.check_access_control(client_addr_tuple[0]): # IP passed to check_access_control
                # Error already logged by check_access_control
                self.sf_server._send_message(client_conn, "error", {"message": "Access denied by relay."})
                return

            # 1. Receive 'submit_recon_job' command from client
            self.logger.debug("Waiting for 'submit_recon_job' command from client.", extra=log_ctx)
            client_job_submission_msg = self.sf_server._receive_message(client_conn) # From original client

            if not client_job_submission_msg or client_job_submission_msg.get("type") != "command" or \
               client_job_submission_msg.get("payload", {}).get("command_name") != "submit_recon_job":
                self.logger.error("Did not receive valid 'submit_recon_job' command from client.", extra={**log_ctx, 'received_message': client_job_submission_msg})
                self.sf_server._send_message(client_conn, "error", {"message": "Invalid job submission command."})
                return
            
            client_job_payload = client_job_submission_msg.get("payload", {})
            client_files_info = client_job_payload.get("files", [])
            client_recon_options_json = client_job_payload.get("client_recon_options_json", "{}")
            log_ctx['num_files_from_client'] = len(client_files_info)
            self.logger.info(f"Received 'submit_recon_job' from client for {len(client_files_info)} files.", extra=log_ctx)

            # 2. Receive files from client and store them in current_relay_job_temp_dir
            received_files_on_relay = []
            for file_info in client_files_info:
                original_path = file_info.get('original_path_on_client')
                expected_name = os.path.basename(file_info.get('name', f"file_{uuid.uuid4().hex[:6]}"))
                if not original_path:
                    self.logger.error(f"Missing 'original_path_on_client' for file.", extra={**log_ctx, 'file_info': file_info})
                    self.sf_server._send_message(client_conn, "error", {"message": f"Relay Error: Missing original_path_on_client for {expected_name}."})
                    raise ValueError("Missing original_path_on_client")

                self.logger.debug(f"Requesting file from client.", extra={**log_ctx, 'original_client_path': original_path, 'expected_name': expected_name})
                if not self.sf_server.request_file_from_client(client_conn, original_path):
                    self.logger.error(f"Failed to send 'request_file' to client for file.", extra={**log_ctx, 'original_client_path': original_path})
                    raise ConnectionAbortedError(f"Relay failed to request file {original_path} from client.")
                
                saved_path_on_relay = self.sf_server.receive_file_securely(client_conn, expected_filename=expected_name, save_dir_override=current_relay_job_temp_dir)
                if not saved_path_on_relay:
                    self.logger.error(f"Failed to receive file from client.", extra={**log_ctx, 'expected_name': expected_name})
                    self.sf_server._send_message(client_conn, "error", {"message": f"Relay Error: Failed receiving file {expected_name}."})
                    raise ConnectionAbortedError(f"Relay failed receiving file {expected_name} from client.")
                received_files_on_relay.append({"name": expected_name, "path_on_relay": saved_path_on_relay})
                self.logger.info(f"Received file from client and stored on relay.", extra={**log_ctx, 'expected_name': expected_name, 'relay_path': saved_path_on_relay})
            
            # 3. Select backend server
            backend_server_info = self.select_backend_server() # Logs internally
            if not backend_server_info:
                self.logger.error("No healthy backend server available.", extra=log_ctx)
                self.sf_server._send_message(client_conn, "job_failed", {"relay_job_id": relay_job_id, "error": "No healthy backend server available at the relay."})
                return
            log_ctx['backend_server'] = backend_server_info['name']
            self.logger.info(f"Selected backend server.", extra=log_ctx)

            # 4. Forward job to backend
            backend_sft_client = SecureFileTransferClient(
                host=backend_server_info['host'], 
                port=backend_server_info['port'], 
                shared_key=self.shared_key_for_backends, # Use the specific key for backends
                logger=self.logger.getChild(f"SFTClientToBackend.{backend_server_info['name'].replace(':', '_')}")
            )
            if not backend_sft_client.connect():
                self.logger.error(f"Relay failed to connect to backend server.", extra=log_ctx)
                self.sf_server._send_message(client_conn, "job_failed", {"relay_job_id": relay_job_id, "error": "Relay failed to connect to backend server."})
                return
            self.logger.info("Relay connected to backend server.", extra=log_ctx)
            
            # Prepare payload for backend
            backend_files_payload = [{"name": f_meta["name"], "original_path_on_client": f_meta["path_on_relay"]} for f_meta in received_files_on_relay]
            backend_job_submission_payload = {
                "command_name": "submit_recon_job", # This is what server_app.py expects
                "files": backend_files_payload,
                "client_recon_options_json": client_recon_options_json 
            }

            self.logger.debug("Sending 'submit_recon_job' command to backend.", extra=log_ctx)
            if not backend_sft_client.send_command("submit_recon_job", backend_job_submission_payload): # Use generic send_command
                self.logger.error("Relay failed to send 'submit_recon_job' command to backend.", extra=log_ctx)
                self.sf_server._send_message(client_conn, "job_failed", {"relay_job_id": relay_job_id, "error": "Relay failed to send command to backend."})
                return

            # Handle file requests from backend
            self.logger.debug("Waiting for backend server messages (file requests, job_queued).", extra=log_ctx)
            backend_job_id = None
            while True: # Loop for backend interaction related to this submission
                backend_message = backend_sft_client._receive_message() # Relay's client receives from backend server
                if not backend_message:
                    self.logger.error("Relay lost connection to backend server during job submission.", extra=log_ctx)
                    self.sf_server._send_message(client_conn, "job_failed", {"relay_job_id": relay_job_id, "error": "Relay lost connection to backend."})
                    raise ConnectionAbortedError("Relay lost connection to backend.")

                backend_msg_type = backend_message.get("type")
                backend_payload = backend_message.get("payload", {})
                log_ctx_backend_msg = {**log_ctx, 'backend_msg_type': backend_msg_type, 'backend_payload': backend_payload}

                if backend_msg_type == "request_file":
                    filepath_requested_by_backend = backend_payload.get("filepath") # This path is on the relay
                    self.logger.info(f"Backend server requested file.", extra={**log_ctx_backend_msg, 'requested_file_on_relay': filepath_requested_by_backend})
                    if os.path.exists(filepath_requested_by_backend): # Check if file exists on relay
                        if not backend_sft_client.send_file(filepath_requested_by_backend): # Relay's client sends to backend server
                            self.logger.error(f"Relay failed to send file to backend.", extra={**log_ctx_backend_msg, 'file_path_on_relay': filepath_requested_by_backend})
                            raise ConnectionAbortedError("Relay failed to send file to backend.")
                        self.logger.debug(f"Relay successfully sent file to backend.", extra={**log_ctx_backend_msg, 'file_path_on_relay': filepath_requested_by_backend})
                    else:
                        self.logger.error(f"File requested by backend not found on relay.", extra={**log_ctx_backend_msg, 'missing_file_on_relay': filepath_requested_by_backend})
                        # Notify backend of error
                        backend_sft_client._send_message("error_request_file", {"filepath": filepath_requested_by_backend, "detail": "File not found on relay."})
                        raise FileNotFoundError(f"File {filepath_requested_by_backend} not found on relay for backend.")
                
                elif backend_msg_type == "job_queued":
                    backend_job_id = backend_payload.get("job_id")
                    log_ctx['backend_job_id'] = backend_job_id
                    self.logger.info("Job successfully queued on backend server.", extra=log_ctx)
                    job_successfully_relayed_to_backend = True
                    
                    # Store job tracking info
                    with self.job_tracking_lock:
                        self.active_relayed_jobs[relay_job_id] = {
                            'original_client_addr': client_addr_tuple, # For identifying client if needed
                            'original_client_conn': client_conn, # Keep original client connection
                            'backend_sft_client': backend_sft_client,
                            'backend_job_id': backend_job_id,
                            'relay_temp_job_dir': current_relay_job_temp_dir,
                            'submission_time': time.time()
                        }
                    
                    # Notify original client
                    self.sf_server.send_command_to_client(client_conn, "job_relayed_and_queued", {
                        "relay_job_id": relay_job_id, 
                        "backend_job_id": backend_job_id,
                        "backend_server_name": backend_server_info['name'],
                        "message": "Job successfully relayed and queued on backend."
                    })
                    # Now, this thread needs to transition to relaying results back
                    # For now, we stop here for this part of the subtask.
                    self.logger.info("Job submission relay complete. Result relaying TBD.", extra=log_ctx)
                    # TODO: Implement result relaying logic here by listening to backend_sft_client
                    # and forwarding to client_conn. This would be a new loop.
                    # For now, we assume the client will disconnect or this thread will end.
                    # In a full implementation, this thread would stay alive to manage the result relay.
                    return # End of this simplified submission relay

                elif backend_msg_type == "error":
                    self.logger.error(f"Backend server returned an error during job submission.", extra=log_ctx_backend_msg)
                    self.sf_server._send_message(client_conn, "job_failed", {"relay_job_id": relay_job_id, "error": f"Backend error: {backend_payload.get('message')}"})
                    return # Stop processing this job
                else:
                    self.logger.warning(f"Relay received unexpected message from backend during submission.", extra=log_ctx_backend_msg)
                    # Potentially an issue, decide if to continue or abort

        except Exception as e:
            self.logger.error("Error during job relay process.", exc_info=True, extra=log_ctx)
            if client_conn and not client_conn._closed: # Check if socket is not already closed
                try:
                    self.sf_server._send_message(client_conn, "job_failed", {"relay_job_id": relay_job_id, "error": f"Relay internal error: {str(e)}"})
                except Exception as e_send:
                    self.logger.error("Failed to send final error to client.", exc_info=True, extra={**log_ctx, 'send_error': str(e_send)})
        finally:
            if backend_sft_client and backend_sft_client.is_connected():
                backend_sft_client.disconnect()
            
            if not job_successfully_relayed_to_backend: # If job wasn't successfully handed off to backend
                 if client_conn and not client_conn._closed: client_conn.close() # Close original client connection
                 if client_addr_tuple in self.active_client_connections: del self.active_client_connections[client_addr_tuple]
            
            # If we are not keeping the connection open for result relaying, clean up now.
            # Otherwise, cleanup should happen after results are relayed or if client disconnects.
            if current_relay_job_temp_dir and os.path.isdir(current_relay_job_temp_dir) and not job_successfully_relayed_to_backend : # Example partial cleanup
                self.logger.info(f"Cleaning up temporary relay directory for incomplete job.", extra={**log_ctx, 'cleanup_dir': current_relay_job_temp_dir})
                shutil.rmtree(current_relay_job_temp_dir, ignore_errors=True)

            # Remove from active_client_connections if the connection is being fully terminated by this handler
            # This part is tricky if the thread is supposed to live on for result relaying.
            # For now, assuming this thread ends after this initial phase.
            if client_addr_tuple in self.active_client_connections and not job_successfully_relayed_to_backend:
                 del self.active_client_connections[client_addr_tuple]
            
            self.client_handling_threads = [t for t in self.client_handling_threads if t.is_alive()]
            self.logger.info("Client connection handling finished.", extra=log_ctx)


    # ... (admin command handlers, health checks, etc. remain, ensure logging is updated there too) ...
    def handle_admin_command(self, conn, addr, log_ctx_admin_conn): # Receive context
        self.logger.info("Admin command connection started.", extra=log_ctx_admin_conn)
        response_payload = {"status": "error", "message": "Invalid admin command"}
        try:
            message = self.admin_sf_server._receive_message(conn)
            if message and message.get("type") == "admin_command":
                command_payload = message.get("payload", {})
                command = command_payload.get("command")
                params = command_payload.get("params", {}) # Added to get params for admin commands
                log_ctx_admin_cmd = {**log_ctx_admin_conn, 'admin_command': command, 'admin_params': params}
                self.logger.info("Received admin command.", extra=log_ctx_admin_cmd)

                if command == "get_status": response_payload = self._handle_get_status_command()
                elif command == "get_backend_health": response_payload = self._handle_get_backend_health_command()
                elif command == "get_connected_clients": response_payload = self._handle_get_connected_clients_command()
                else:
                    self.logger.warning("Unknown admin command received.", extra=log_ctx_admin_cmd)
                    response_payload = {"status": "error", "message": f"Unknown admin command: {command}"}
            else:
                self.logger.warning("Invalid message type from admin client.", extra={**log_ctx_admin_conn, 'received_message': message})
                response_payload = {"status": "error", "message": "Invalid message type for admin interface."}
        except Exception as e:
            self.logger.error("Error handling admin command.", exc_info=True, extra=log_ctx_admin_conn)
            response_payload = {"status": "error", "message": f"Server error processing admin command: {str(e)}"}
        finally:
            if self.admin_sf_server: self.admin_sf_server._send_message(conn, "admin_response", response_payload)
            if conn: conn.close()
            self.admin_handling_threads = [t for t in self.admin_handling_threads if t.is_alive()]
            self.logger.info("Admin connection closed.", extra=log_ctx_admin_conn)

    def _handle_get_status_command(self):
        uptime_seconds = time.time() - self.start_time
        uptime_formatted = time.strftime("%Hh %Mm %Ss", time.gmtime(uptime_seconds))
        active_relayed_job_count = 0
        with self.job_tracking_lock:
            active_relayed_job_count = len(self.active_relayed_jobs)

        payload = {
            "status": "success", "relay_status": "running", "uptime": uptime_formatted,
            "connected_clients_count": len(self.active_client_connections), # Main port connections
            "active_relayed_jobs_count": active_relayed_job_count, # Jobs being actively relayed
            "active_client_handler_threads": len([t for t in self.client_handling_threads if t.is_alive()]),
            "active_admin_handler_threads": len([t for t in self.admin_handling_threads if t.is_alive()]),
            "backend_server_count": len(self.backend_servers_list)
        }
        self.logger.debug("Relay status command processed.", extra=payload)
        return payload

    def _handle_get_backend_health_command(self):
        # ... (ensure logging uses extra for context)
        backends_health = [{'name': b.get('name'), 'host': b.get('host'), 'port': b.get('port'), 'healthy': b.get('healthy', False)} for b in self.backend_servers_list]
        payload = {"status": "success", "backends": backends_health}
        self.logger.debug("Backend health command processed.", extra={'backends_count': len(backends_health)})
        return payload

    def _handle_get_connected_clients_command(self):
        # ... (ensure logging uses extra for context)
        clients_info = [{'ip_address': v['ip'], 'port': v['port'], 
                         'connected_since_utc': time.strftime("%Y-%m-%d %H:%M:%S UTC", time.gmtime(v['connect_time'])), 
                         'duration_seconds': int(time.time() - v['connect_time']),
                         'relay_job_id': v.get('relay_job_id')} 
                        for k, v in list(self.active_client_connections.items())]
        payload = {"status": "success", "clients": clients_info, "count": len(clients_info)}
        self.logger.debug("Connected clients command processed.", extra={'client_count': len(clients_info)})
        return payload
    
    def check_access_control(self, client_ip: str) -> bool:
        # ... (ensure logging uses extra for context)
        trusted_ips_str = self.config.get('TRUSTED_CLIENT_IPS', '')
        log_ctx = {'client_ip': client_ip, 'trusted_ips_config': trusted_ips_str if trusted_ips_str else "None (Allow All)"}
        if not trusted_ips_str:
            self.logger.debug("TRUSTED_CLIENT_IPS not set. Allowing access.", extra=log_ctx)
            return True
        
        trusted_ips_list = [ip.strip() for ip in trusted_ips_str.split(',') if ip.strip()]
        if client_ip in trusted_ips_list:
            self.logger.info("Access granted for trusted IP.", extra=log_ctx)
            return True
        else:
            self.logger.warning("Access denied for IP. Not in TRUSTED_CLIENT_IPS list.", extra={**log_ctx, 'configured_trusted_ips': trusted_ips_list})
            return False

    def perform_health_checks(self):
        # ... (ensure logging uses extra for context)
        log_ctx_hc_start = {'thread_name': threading.current_thread().name}
        self.logger.info("Performing health checks on backend servers...", extra=log_ctx_hc_start)
        for server_info in self.backend_servers_list:
            backend_name = server_info.get('name', f"{server_info['host']}:{server_info['port']}")
            log_ctx_backend = {**log_ctx_hc_start, 'backend_name': backend_name, 'backend_host': server_info['host'], 'backend_port': server_info['port']}
            try:
                with socket.create_connection((server_info['host'], server_info['port']), timeout=5):
                    if not server_info.get('healthy'): 
                        self.logger.info(f"Backend server is now healthy.", extra=log_ctx_backend)
                    server_info['healthy'] = True
            except (socket.error, socket.timeout) as e:
                if server_info.get('healthy', True): 
                    self.logger.warning(f"Backend server is now unhealthy.", extra={**log_ctx_backend, 'error_details': str(e)})
                server_info['healthy'] = False
        self.report_status()

    def report_status(self):
        # ... (ensure logging uses extra for context)
        healthy_backends = [s['name'] for s in self.backend_servers_list if s['healthy']]
        unhealthy_backends = [s['name'] for s in self.backend_servers_list if not s['healthy']]
        active_relayed_job_count = 0
        with self.job_tracking_lock:
            active_relayed_job_count = len(self.active_relayed_jobs)
        status_extra = {
            'healthy_backend_count': len(healthy_backends), 'unhealthy_backend_count': len(unhealthy_backends),
            'healthy_backends': healthy_backends, 'unhealthy_backends': unhealthy_backends,
            'connected_clients_count': len(self.active_client_connections),
            'active_relayed_jobs_count': active_relayed_job_count
        }
        self.logger.info("Relay server status report.", extra=status_extra)

    def select_backend_server(self) -> dict | None:
        # ... (ensure logging uses extra for context)
        if not self.backend_servers_list:
            self.logger.error("No backend servers configured to select from.")
            return None

        healthy_servers = [s for s in self.backend_servers_list if s['healthy']]
        if not healthy_servers:
            self.logger.error("No healthy backend servers available for selection.")
            return None

        num_healthy = len(healthy_servers)
        selected_index = self.current_backend_index % num_healthy
        selected_server = healthy_servers[selected_index]
        self.current_backend_index = (self.current_backend_index + 1) % num_healthy
        
        self.logger.info("Selected backend server.", extra={'selected_backend': selected_server['name'], 'selection_method': 'round_robin', 'healthy_server_count': num_healthy})
        return selected_server

def main():
    # ... (main function remains largely the same, initial prints are fine before logger is fully set up by setup_logging)
    global RELAY_CONFIG, logger 

    print(json.dumps({"timestamp": time.strftime('%Y-%m-%dT%H:%M:%S%z'), "level": "INFO", "name": "__main__", "message": "Relay application starting up..."}))
    
    opts_file = 'relay.opts'
    if not os.path.exists(opts_file):
        print(json.dumps({"timestamp": time.strftime('%Y-%m-%dT%H:%M:%S%z'), "level": "INFO", "name": "__main__", "message": f"'{opts_file}' not found. Creating default."}))
        try: readoptions(opts_file) 
        except Exception as e:
            print(json.dumps({"timestamp": time.strftime('%Y-%m-%dT%H:%M:%S%z'), "level": "CRITICAL", "name": "__main__", "message": f"ERROR creating default '{opts_file}': {e}", "error_details": str(e)}))
            sys.exit(1)
            
    RELAY_CONFIG = readoptions(opts_file) 
    setup_logging() 
    
    logger.info("Relay application starting with loaded configuration.", extra={'config_source': opts_file})
    if not RELAY_CONFIG:
        logger.critical("Configuration could not be loaded. Exiting.", extra={'config_source': opts_file})
        sys.exit(1)

    if RELAY_CONFIG.get('SHARED_KEY_RELAY_TO_CLIENTS', '') == 'SET_YOUR_RELAY_TO_CLIENTS_KEY_HERE' or \
       not RELAY_CONFIG.get('SHARED_KEY_RELAY_TO_CLIENTS'):
        logger.critical("CRITICAL SECURITY WARNING: SHARED_KEY_RELAY_TO_CLIENTS is not set or placeholder. Client-facing relay is insecure.", extra={'security_issue': 'invalid_main_relay_key'})

    app = None
    try:
        app = RelayServerApp(RELAY_CONFIG)
        if not app.start():
            logger.critical("Relay Server application failed to start properly. Exiting.")
            sys.exit(1)
    except KeyboardInterrupt:
        logger.info("Relay Server shutting down due to KeyboardInterrupt.")
    except Exception as e:
        logger.critical("Relay Server failed with an unexpected error.", exc_info=True, extra={'error_details': str(e)})
    finally:
        if app is not None:
            app.stop()
        logger.info("Relay Server application fully stopped.")
        print(json.dumps({"timestamp": time.strftime('%Y-%m-%dT%H:%M:%S%z'), "level": "INFO", "name": "__main__", "message": "Relay application terminated."}))

if __name__ == "__main__":
    main()

```
