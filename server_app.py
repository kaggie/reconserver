# -*- coding: utf-8 -*-
"""
server_app.py: Main application for the Recon Server.

Handles client connections, PFILE reception, job queuing, script execution,
and status/queue management commands.
"""
import os
import socket
import subprocess
import traceback
import time
import json
import queue
import threading
import uuid
import sys
import shutil
import psutil # For resource checking
import logging # New import
from pythonjsonlogger import jsonlogger # New import

try:
    from reconlibs import readoptions
    from secure_transfer import SecureFileTransferServer
except ImportError as e:
    # Basic print for critical startup error before logger is available
    print(json.dumps({
        "timestamp": time.strftime('%Y-%m-%dT%H:%M:%S%z'), "level": "CRITICAL", "name": __name__, 
        "message": f"Could not import necessary modules: {e}. Ensure reconlibs.py and secure_transfer.py are in PYTHONPATH."
    }))
    sys.exit(1)

class ReconServerApp:
    # DEBUG flag from config might influence log level if not explicitly set by LOG_LEVEL
    KEEPALIVE = True 

    def __init__(self, options_file: str = "recon.opts"):
        self.options_file = options_file
        self.server_hostname: str = "localhost"
        self.server_port: int = 60000
        self.shared_key: str = ""
        self.recon_server_base_pfile_dir: str = "/tmp/recon_server_pfiles"
        self.recon_script_path: str = "default_recon_script.sh"
        self.recon_job_output_base_dir: str = "/tmp/recon_server_job_outputs" 
        self.log_filepath: str = "/tmp/recon_server.log" # Default, overridden by config
        self.log_level_str: str = "INFO" # Default, overridden by config
        self.trusted_ips: list[str] = []
        self.max_concurrent_jobs: int = 1
        
        self.max_cpu_load: int = 75 
        self.min_available_memory: int = 500 
        self.resource_check_interval: int = 10 
        self.start_time = time.time()

        self.admin_sf_server = None
        self.admin_listener_thread = None
        self.server_admin_port = 60003 
        self.server_admin_shared_key = "" 
        self.admin_handling_threads = [] 

        self.config = {} 
        self._load_configuration() 
        self._setup_logging() # Setup logging after config (esp. log_filepath and log_level) is loaded
        
        self.logger.info("Initializing ReconServerApp...", extra={'options_file': self.options_file})

        os.makedirs(self.recon_server_base_pfile_dir, exist_ok=True)
        os.makedirs(self.recon_job_output_base_dir, exist_ok=True)

        self.sf_server = SecureFileTransferServer(
            host=self.server_hostname,
            port=self.server_port,
            shared_key=self.shared_key,
            download_dir=self.recon_server_base_pfile_dir,
            logger=self.logger # Pass logger to SecureFileTransferServer
        )
        
        self.job_queue: queue.Queue = queue.Queue()
        self.shutdown_event = threading.Event()
        self.worker_threads: list[threading.Thread] = []
        self.worker_statuses = {} # Thread-ID to status mapping
        
        self.logger.info("ReconServerApp initialized.", extra={
            'max_concurrent_jobs': self.max_concurrent_jobs, 
            'recon_server_base_pfile_dir': self.recon_server_base_pfile_dir,
            'recon_job_output_base_dir': self.recon_job_output_base_dir
        })
        if not self.shared_key or self.shared_key == "SET_YOUR_SHARED_KEY_HERE":
            self.logger.critical("Main SHARED_KEY is not set or is a placeholder. Client communication is insecure.", extra={'security_issue': 'invalid_main_shared_key'})

    def _setup_logging(self):
        self.logger = logging.getLogger(self.__class__.__name__) # Logger for this class
        # Prevent propagation to root logger if it already has handlers, to avoid duplicate console logs
        self.logger.propagate = False 
        
        log_level = getattr(logging, self.log_level_str.upper(), logging.INFO)
        self.logger.setLevel(log_level)

        formatter = jsonlogger.JsonFormatter(
            '%(asctime)s %(levelname)s %(name)s %(threadName)s %(module)s %(funcName)s %(lineno)d %(message)s',
            timestamp=True 
        )

        # Console Handler
        stream_handler = logging.StreamHandler(sys.stdout)
        stream_handler.setFormatter(formatter)
        stream_handler.setLevel(log_level) 
        self.logger.addHandler(stream_handler)

        if self.log_filepath:
            try:
                log_dir = os.path.dirname(self.log_filepath)
                if log_dir and not os.path.exists(log_dir):
                    os.makedirs(log_dir, exist_ok=True)
                
                file_handler = logging.FileHandler(self.log_filepath, mode='a')
                file_handler.setFormatter(formatter)
                file_handler.setLevel(log_level)
                self.logger.addHandler(file_handler)
                self.logger.info("Logging configured to console and file.", extra={'log_filepath': self.log_filepath, 'log_level': self.log_level_str})
            except Exception as e:
                self.logger.error(f"Failed to set up file logging.", exc_info=True, extra={'log_filepath': self.log_filepath, 'error_details': str(e)})
                self.logger.info("Logging configured to console only.", extra={'log_level': self.log_level_str})
        else:
            self.logger.info("Logging configured to console only (no log_filepath specified).", extra={'log_level': self.log_level_str})
        
        # Also configure logger for SecureFileTransferServer if possible, or pass self.logger to it.
        # For now, SecureFileTransferServer might use its own logger or print statements.

    def _load_configuration(self):
        # This method runs before the logger is fully set up. Use basic print for critical config errors.
        print(json.dumps({"timestamp": time.strftime('%Y-%m-%dT%H:%M:%S%z'), "level": "INFO", "name": self.__class__.__name__, "message": f"Loading configuration from '{self.options_file}'..."}))
        
        try:
            config_dict = readoptions(self.options_file)
            self.config = config_dict

            self.server_hostname = self.config.get('SERVER_HOSTNAME', 'localhost')
            self.server_port = int(self.config.get('SERVER_PORT', 60000))
            self.recon_server_base_pfile_dir = self.config.get('RECON_SERVER_BASE_PFILE_DIR', '/tmp/recon_server_pfiles')
            self.recon_script_path = self.config.get('RECON_SCRIPT_PATH', 'default_recon_script.sh')
            self.recon_job_output_base_dir = self.config.get('RECON_JOB_OUTPUT_BASE_DIR', '/tmp/recon_server_job_outputs')
            self.log_filepath = self.config.get('LOG_FILEPATH', '/tmp/recon_server.log')
            self.log_level_str = self.config.get('LOG_LEVEL', 'INFO').upper() # For _setup_logging
            self.shared_key = self.config.get('SHARED_KEY', 'SET_YOUR_SHARED_KEY_HERE')
            
            self.server_admin_port = int(self.config.get('SERVER_ADMIN_PORT', 60003))
            self.server_admin_shared_key = self.config.get('SERVER_ADMIN_SHARED_KEY', '')
            if not self.server_admin_shared_key or self.server_admin_shared_key == 'SET_YOUR_SERVER_ADMIN_KEY_HERE':
                print(json.dumps({"timestamp": time.strftime('%Y-%m-%dT%H:%M:%S%z'), "level": "WARNING", "name": self.__class__.__name__, "message": "SERVER_ADMIN_SHARED_KEY is not set or is a placeholder. Admin interface will NOT start.", "security_issue": "invalid_admin_key"}))
                self.server_admin_shared_key = "" 

            self.max_cpu_load = int(self.config.get('MAX_CPU_LOAD_PERCENT', 75))
            self.min_available_memory = int(self.config.get('MIN_AVAILABLE_MEMORY_MB', 500))
            self.resource_check_interval = int(self.config.get('RESOURCE_CHECK_INTERVAL_SECONDS', 10))

            if not (0 < self.max_cpu_load <= 100): self.max_cpu_load = 75
            if self.min_available_memory < 0: self.min_available_memory = 0
            if self.resource_check_interval <= 0: self.resource_check_interval = 10
            
            self.max_concurrent_jobs = int(self.config.get('MAX_CONCURRENT_JOBS', 1))
            if self.max_concurrent_jobs <= 0: self.max_concurrent_jobs = 1
            
            ips_str = self.config.get('TRUSTED_IPS', '')
            self.trusted_ips = [ip.strip() for ip in ips_str.split(',') if ip.strip()] if ips_str else []
            
            self.DEBUG = self.config.get('DEBUG', False) # For any remaining direct DEBUG checks

        except ValueError as e:
            print(json.dumps({"timestamp": time.strftime('%Y-%m-%dT%H:%M:%S%z'), "level": "CRITICAL", "name": self.__class__.__name__, "message": f"Error parsing numeric configuration value: {e}. Please check '{self.options_file}'.", "error_details": str(e)}))
            raise
        except FileNotFoundError:
            print(json.dumps({"timestamp": time.strftime('%Y-%m-%dT%H:%M:%S%z'), "level": "CRITICAL", "name": self.__class__.__name__, "message": f"Options file '{self.options_file}' not found. Cannot start."}))
            raise
        except Exception as e:
            print(json.dumps({"timestamp": time.strftime('%Y-%m-%dT%H:%M:%S%z'), "level": "CRITICAL", "name": self.__class__.__name__, "message": f"Unexpected error loading configuration from '{self.options_file}': {e}", "error_details": str(e), "traceback": traceback.format_exc()}))
            raise
    
    def _validate_ip(self, client_ip: str) -> bool:
        if not self.trusted_ips: return True
        if client_ip in self.trusted_ips: return True
        self.logger.warning("IP not trusted. Denying.", extra={'client_ip': client_ip, 'action': 'deny_untrusted_ip'})
        return False

    def _trigger_external_script(self, input_path_or_dir: str, client_options_dict: dict | None = None, job_id: str | None = None, job_output_dir_for_script: str | None = None) -> bool:
        script_to_execute = self.recon_script_path
        log_extra = {'job_id': job_id, 'script_path': script_to_execute, 'input_dir': input_path_or_dir, 'output_dir': job_output_dir_for_script, 'script_options': client_options_dict or {}}
        self.logger.debug(f"Triggering script '{script_to_execute}'.", extra=log_extra)
        
        command = []
        base_command_args = [input_path_or_dir]
        if job_output_dir_for_script:
            base_command_args.extend(["--output-dir", job_output_dir_for_script])

        if script_to_execute.lower().endswith('.py'):
            command = ["python", script_to_execute] + base_command_args
            if client_options_dict:
                for key, value in client_options_dict.items(): command.extend([f"--{key.replace('_', '-')}", str(value)])
        elif script_to_execute.lower().endswith('.m'):
            func = os.path.splitext(os.path.basename(script_to_execute))[0]
            matlab_args_list = [f"'{arg}'" for arg in base_command_args] 
            if client_options_dict:
                for k, v in client_options_dict.items(): matlab_args_list.extend([f"'{k}'", f"'{str(v)}'"])
            args_str = ", ".join(matlab_args_list)
            matlab_cmd = f"try; {func}({args_str}); catch e; disp(e.message); exit(1); end; exit(0);"
            command = ["matlab", "-batch", matlab_cmd]
        else: 
            command = [script_to_execute] + base_command_args
            if client_options_dict:
                for k, v in client_options_dict.items(): command.extend([f"--{k.replace('_', '-')}", str(v)])
        
        self.logger.info(f"Executing script command: {' '.join(command)}", extra=log_extra)
        script_dir = os.path.dirname(script_to_execute) if os.path.isabs(script_to_execute) else None
        
        try:
            process = subprocess.run(command, cwd=script_dir, capture_output=True, text=True, check=False, timeout=1800)
            script_log_extra = {**log_extra, 'script_rc': process.returncode, 'script_stdout': process.stdout.strip() if process.stdout else "", 'script_stderr': process.stderr.strip() if process.stderr else ""}
            if process.returncode == 0:
                self.logger.info("Script execution successful.", extra=script_log_extra)
            else:
                self.logger.error("Script execution failed.", extra=script_log_extra)
            return process.returncode == 0
        except subprocess.TimeoutExpired:
            self.logger.error("Script execution timed out.", extra={**log_extra, 'timeout': 1800})
            return False
        except Exception as e:
            self.logger.error(f"Exception running script.", exc_info=True, extra={**log_extra, 'error_details': str(e)})
            return False

    def _handle_get_server_status(self, conn: socket.socket, client_addr_ip: str):
        self.logger.debug("Handling 'get_server_status' command.", extra={'client_ip': client_addr_ip, 'command_type': 'get_server_status'})
        uptime_seconds = time.time() - self.start_time
        uptime_formatted = time.strftime("%Hh %Mm %Ss", time.gmtime(uptime_seconds))
        payload = {
            "server_uptime": uptime_formatted,
            "configured_max_workers": self.max_concurrent_jobs,
            "current_worker_thread_count": len([t for t in self.worker_threads if t.is_alive()]), 
            "queued_jobs_in_system": self.job_queue.qsize() 
        }
        self.sf_server.send_command_to_client(conn, "server_status_response", payload)

    def _handle_get_queue_details(self, conn: socket.socket, client_addr_ip: str):
        self.logger.debug("Handling 'get_queue_details' command.", extra={'client_ip': client_addr_ip, 'command_type': 'get_queue_details'})
        with self.job_queue.mutex: 
            jobs_snapshot = [job for job in self.job_queue.queue if job] # Filter out None signals
        
        job_details_list = []
        for job_item in jobs_snapshot:
            job_details_list.append({
                "job_id": job_item.get('job_id', 'N/A'),
                "status": job_item.get('status', 'queued'), 
                "primary_input_file": job_item.get('primary_input_file_name', 'N/A'),
                "num_input_files": job_item.get('num_input_files', 0),
                "submitted_at_utc": time.strftime("%Y-%m-%d %H:%M:%S UTC", time.gmtime(job_item.get('submitted_at', 0))),
                "job_input_dir_basename": os.path.basename(job_item.get('job_input_dir_on_server','N/A'))
            })
        payload = {"jobs": job_details_list, "count": len(job_details_list)}
        self.sf_server.send_command_to_client(conn, "queue_details_response", payload)

    def _handle_client_connection(self, conn: socket.socket, client_addr_tuple: tuple[str, int]):
        client_ip = client_addr_tuple[0]
        log_ctx = {'client_ip': client_ip, 'client_port': client_addr_tuple[1], 'thread_name': threading.current_thread().name}
        job_id_for_recon_job = None 
        job_input_dir_for_recon_job = None
        command_name_for_finally = "Unknown"
        
        try:
            self.logger.debug("Waiting for initial command from client.", extra=log_ctx)
            initial_message = self.sf_server._receive_message(conn)

            if not initial_message:
                self.logger.error("No initial message or client disconnected prematurely.", extra=log_ctx)
                if conn: conn.close(); return

            msg_type = initial_message.get("type")
            payload = initial_message.get("payload", {})
            log_ctx['initial_msg_type'] = msg_type
            
            if msg_type != "command":
                self.logger.error(f"Expected 'command' type from client, got '{msg_type}'.", extra=log_ctx)
                if conn: conn.close(); return

            command_name = payload.get("command_name")
            command_name_for_finally = command_name or "Unknown"
            log_ctx['command_name'] = command_name
            
            if command_name == "submit_recon_job":
                job_id_for_recon_job = str(uuid.uuid4())
                job_input_dir_for_recon_job = os.path.join(self.recon_server_base_pfile_dir, f"job_{job_id_for_recon_job}_input")
                log_ctx['job_id'] = job_id_for_recon_job
            
            self.logger.info(f"Received command: {command_name}", extra=log_ctx)

            if command_name == "get_server_status":
                self._handle_get_server_status(conn, client_ip); conn.close(); return
            elif command_name == "get_queue_details":
                self._handle_get_queue_details(conn, client_ip); conn.close(); return
            elif command_name == "submit_recon_job":
                self.logger.debug("Processing 'submit_recon_job'.", extra=log_ctx)

                client_files_payload = payload.get('files', [])
                options_json = payload.get("client_recon_options_json", "{}")
                client_recon_options = json.loads(options_json) if isinstance(options_json, str) else {}
                log_ctx['num_files_from_client'] = len(client_files_payload)
                log_ctx['client_recon_options'] = client_recon_options

                if not client_files_payload :
                    self.logger.error("Invalid or empty 'files' list in submit_recon_job.", extra=log_ctx)
                    self.sf_server.send_command_to_client(conn, "error", {"message": "Job submission: 'files' list missing or empty."}); conn.close(); return
                
                os.makedirs(job_input_dir_for_recon_job, exist_ok=True)
                self.logger.info(f"Created job input directory.", extra={**log_ctx, 'job_input_dir': job_input_dir_for_recon_job})
                received_paths = []
                for file_info in client_files_payload:
                    original_path = file_info.get('original_path_on_client')
                    expected_name = os.path.basename(file_info.get('name', f"file_{uuid.uuid4().hex[:8]}"))
                    if not original_path: 
                        self.logger.error(f"Missing original_path for file '{expected_name}'. Aborting job.", extra={**log_ctx, 'filename': expected_name})
                        raise ValueError(f"Missing original_path for {expected_name}") 

                    self.logger.debug(f"Requesting file from client.", extra={**log_ctx, 'original_path': original_path, 'expected_name': expected_name})
                    if not self.sf_server.request_file_from_client(conn, original_path): 
                        self.logger.error(f"Failed to send 'request_file' for file.", extra={**log_ctx, 'original_path': original_path})
                        raise ConnectionAbortedError(f"Failed to send 'request_file' for {original_path}")
                    
                    received_path = self.sf_server.receive_file_securely(conn, expected_filename=expected_name, save_dir_override=job_input_dir_for_recon_job)
                    if not received_path:
                        self.logger.error(f"Failed receiving file from client.", extra={**log_ctx, 'expected_name': expected_name})
                        raise ConnectionAbortedError(f"Failed receiving {expected_name}")
                    self.logger.info(f"Successfully received file.", extra={**log_ctx, 'filename': expected_name, 'saved_path': received_path})
                    received_paths.append(received_path)
                
                primary_file = os.path.basename(received_paths[0]) if received_paths else "N/A"
                job_data = {
                    "job_id": job_id_for_recon_job, "job_input_dir_on_server": job_input_dir_for_recon_job,
                    "num_input_files": len(received_paths), "primary_input_file_name": primary_file,
                    "client_recon_options": client_recon_options, "client_conn": conn, 
                    "client_addr_tuple": client_addr_tuple, "submitted_at": time.time(), "status": "queued"
                }
                self.job_queue.put(job_data)
                self.logger.info(f"Job queued.", extra={**log_ctx, 'num_files_received': len(received_paths)})
                self.sf_server.send_command_to_client(conn, "job_queued", {"job_id": job_id_for_recon_job, "num_files_received": len(received_paths)})
            else:
                self.logger.warning(f"Unknown command received: {command_name}", extra=log_ctx)
                self.sf_server.send_command_to_client(conn, "error", {"message": f"Unknown command: {command_name}"}); conn.close()
        
        except (socket.error, json.JSONDecodeError, ConnectionAbortedError, ValueError) as e:
            log_ctx['error_details'] = str(e)
            self.logger.error(f"Client handling error ({command_name_for_finally}).", extra=log_ctx, exc_info=False) 
            if command_name_for_finally == "submit_recon_job" and job_input_dir_for_recon_job and os.path.isdir(job_input_dir_for_recon_job): 
                self.logger.info(f"Cleaning up failed job input dir.", extra={**log_ctx, 'failed_job_input_dir': job_input_dir_for_recon_job})
                shutil.rmtree(job_input_dir_for_recon_job, ignore_errors=True)
            if conn: conn.close()
        except Exception as e:
            log_ctx['error_details'] = str(e)
            self.logger.critical(f"Unexpected critical error with client ({command_name_for_finally}).", exc_info=True, extra=log_ctx)
            if command_name_for_finally == "submit_recon_job" and job_input_dir_for_recon_job and os.path.isdir(job_input_dir_for_recon_job): 
                self.logger.info(f"Cleaning up failed job input dir due to critical error.", extra={**log_ctx, 'failed_job_input_dir': job_input_dir_for_recon_job})
                shutil.rmtree(job_input_dir_for_recon_job, ignore_errors=True)
            if conn: 
                try: self.sf_server._send_message(conn, "error", {"message": f"Unexpected server error: {str(e)}"})
                except: pass 
                conn.close()

    def _job_worker_loop(self):
        thread_id = threading.get_ident()
        worker_name = threading.current_thread().name 
        job_id_being_processed = None 
        log_ctx_worker = {'worker_name': worker_name, 'worker_thread_id': thread_id}

        self.logger.info("Worker started.", extra=log_ctx_worker)
        
        self.worker_statuses[thread_id] = {"status": "idle", "job_id": None, "started_at": time.time(), "name": worker_name}

        while not self.shutdown_event.is_set():
            self.worker_statuses[thread_id].update({"status": "idle", "job_id": None})
            job_id_being_processed = None

            while not self.shutdown_event.is_set():
                try:
                    cpu_load = psutil.cpu_percent(interval=0.5) 
                    mem_info = psutil.virtual_memory()
                    available_memory_mb = mem_info.available / (1024 * 1024)
                    resource_extra = {**log_ctx_worker, 'cpu_load': cpu_load, 'available_memory_mb': available_memory_mb, 'max_cpu_load': self.max_cpu_load, 'min_available_memory_mb': self.min_available_memory}
                except Exception as e:
                    self.logger.warning("Could not check system resources. Proceeding as if available.", exc_info=True, extra=log_ctx_worker)
                    cpu_load = 0 
                    available_memory_mb = self.min_available_memory + 1 
                    resource_extra = {**log_ctx_worker, 'cpu_load': 'error_checking', 'available_memory_mb': 'error_checking'}


                if cpu_load < self.max_cpu_load and available_memory_mb > self.min_available_memory:
                    self.logger.debug("Resources OK. Checking for jobs.", extra=resource_extra)
                    break 
                else:
                    self.worker_statuses[thread_id]["status"] = f"waiting_resource (CPU:{cpu_load:.1f} Mem:{available_memory_mb:.0f})"
                    self.logger.info("Resource constraints hit. Waiting.", extra=resource_extra)
                    if self.shutdown_event.wait(timeout=float(self.resource_check_interval)):
                        self.logger.info("Shutdown signaled during resource wait.", extra=log_ctx_worker)
                        break 
            
            self.worker_statuses[thread_id]["status"] = "idle" 

            if self.shutdown_event.is_set():
                self.logger.info("Exiting due to shutdown signal.", extra=log_ctx_worker)
                break 

            job = None; conn_to_client = None; job_id = "N/A"; client_ip = "N/A"
            job_input_dir = None; job_output_dir = None 
            log_ctx_job = {} 
            try:
                job = self.job_queue.get(timeout=1) 
                if job is None: 
                    self.job_queue.task_done()
                    self.logger.info("Received None from queue, preparing to exit.", extra=log_ctx_worker)
                    break 
                
                job_id = job["job_id"]
                job_id_being_processed = job_id 
                job["status"] = "processing" 
                self.worker_statuses[thread_id].update({"status": f"processing_job_{job_id}", "job_id": job_id})
                
                conn_to_client = job["client_conn"]; client_ip = job["client_addr_tuple"][0]
                job_input_dir = job['job_input_dir_on_server']
                primary_file_name = job.get("primary_input_file_name", "N/A")
                log_ctx_job = {'job_id': job_id, 'client_ip': client_ip, **log_ctx_worker, 'primary_file': primary_file_name}

                job_output_dir = os.path.join(self.recon_job_output_base_dir, f"job_{job_id}_output")
                os.makedirs(job_output_dir, exist_ok=True)
                job["job_output_dir_on_server"] = job_output_dir 
                
                self.logger.info(f"Starting processing for job.", extra={**log_ctx_job, 'input_dir': job_input_dir, 'output_dir': job_output_dir})
                
                success = self._trigger_external_script(
                    input_path_or_dir=job_input_dir, 
                    client_options_dict=job['client_recon_options'], 
                    job_id=job_id,
                    job_output_dir_for_script=job_output_dir 
                )
                
                if success:
                    if not os.path.isdir(job_output_dir): 
                        self.logger.error(f"Job output directory not found after script execution.", extra={**log_ctx_job, 'job_output_dir': job_output_dir})
                        dicoms_in_job_output_dir = []
                    else:
                        dicoms_in_job_output_dir = [f for f in os.listdir(job_output_dir) if os.path.isfile(os.path.join(job_output_dir, f))]
                    
                    log_ctx_job_results = {**log_ctx_job, 'output_file_count': len(dicoms_in_job_output_dir)}
                    if not dicoms_in_job_output_dir:
                        self.logger.info("No output files found in job output directory.", extra=log_ctx_job_results)
                        self.sf_server.send_command_to_client(conn_to_client, "recon_status", {"job_id": job_id, "status": "completed_no_dicoms", "pfile": primary_file_name, "detail": f"Script ran but no output files found in {job_output_dir}."})
                    else:
                        self.logger.info(f"Found {len(dicoms_in_job_output_dir)} output file(s). Starting transfer.", extra=log_ctx_job_results)
                        ack_dicom_start = self.sf_server.send_command_to_client(conn_to_client, "dicom_transfer_start", {"job_id": job_id, "num_files": len(dicoms_in_job_output_dir)})
                        if ack_dicom_start and ack_dicom_start.get("status") == "ready":
                            for i, d_name in enumerate(dicoms_in_job_output_dir):
                                file_path_to_send = os.path.join(job_output_dir, d_name)
                                self.logger.debug(f"Sending output file {i+1}/{len(dicoms_in_job_output_dir)}.", extra={**log_ctx_job_results, 'output_file_name': d_name})
                                if not self.sf_server.send_file_to_client(conn_to_client, file_path_to_send): 
                                    self.logger.error(f"Failed to send output file.", extra={**log_ctx_job_results, 'output_file_name': d_name})
                                    break 
                        else:
                             self.logger.warning("Client not ready for DICOMs or failed to acknowledge.", extra={**log_ctx_job_results, 'client_ack': ack_dicom_start})
                    
                    self.logger.info(f"Job processing and result transfer phase complete.", extra=log_ctx_job)
                    self.sf_server.send_command_to_client(conn_to_client, "recon_complete", {"job_id": job_id, "pfile": primary_file_name, "message": f"Reconstruction script completed. Results processed from {job_output_dir}."})
                else: 
                    self.logger.error("Reconstruction script failed or reported an error.", extra=log_ctx_job)
                    self.sf_server.send_command_to_client(conn_to_client, "job_failed", {"job_id": job_id, "pfile": primary_file_name, "error": "Reconstruction script failed or reported an error."})
            
            except socket.error as e:
                self.logger.error(f"Worker socket error.", exc_info=True, extra=log_ctx_job if job_id != "N/A" else log_ctx_worker)
            except Exception as e: 
                self.logger.critical(f"Unexpected worker error.", exc_info=True, extra=log_ctx_job if job_id != "N/A" else log_ctx_worker)
                if conn_to_client:
                    try: self.sf_server.send_command_to_client(conn_to_client, "job_failed", {"job_id": job_id, "pfile": job.get("primary_input_file_name","N/A") if job else "N/A", "error": f"Unexpected server error in worker: {str(e)}"})
                    except: self.logger.error("Failed to notify client of unexpected worker error.", exc_info=True, extra=log_ctx_job if job_id != "N/A" else log_ctx_worker)
            finally:
                if job: self.job_queue.task_done()
                if conn_to_client: 
                    try: conn_to_client.close()
                    except: pass
                
                if job_input_dir and os.path.isdir(job_input_dir): 
                    self.logger.info(f"Cleaning up job input dir.", extra={**log_ctx_job, 'input_dir_cleanup': job_input_dir} if job_id != "N/A" else {**log_ctx_worker, 'input_dir_cleanup': job_input_dir})
                    shutil.rmtree(job_input_dir, ignore_errors=True)
                if job_output_dir and os.path.isdir(job_output_dir):
                    self.logger.info(f"Cleaning up job output dir.", extra={**log_ctx_job, 'output_dir_cleanup': job_output_dir} if job_id != "N/A" else {**log_ctx_worker, 'output_dir_cleanup': job_output_dir})
                    shutil.rmtree(job_output_dir, ignore_errors=True)
            
            except queue.Empty: 
                self.worker_statuses[thread_id]["status"] = "idle_queue_empty"
                continue 
        
        self.worker_statuses[thread_id].update({"status": "stopped", "job_id": None})
        self.logger.info("Worker shutting down.", extra=log_ctx_worker)


    def _admin_listener_loop(self):
        """Listens for and handles admin connections."""
        self.logger.info(f"Admin interface listener started.", extra={'admin_port': self.server_admin_port, 'thread_name': threading.current_thread().name})
        try:
            while not self.shutdown_event.is_set():
                if not self.admin_sf_server:
                    self.logger.critical("Admin server not initialized. Admin listener loop cannot run.")
                    break
                conn, addr = self.admin_sf_server.accept_connection() 
                if conn:
                    log_ctx_admin_conn = {'admin_client_ip': addr[0], 'admin_client_port': addr[1]}
                    self.logger.info("Accepted admin connection.", extra=log_ctx_admin_conn)
                    admin_client_thread = threading.Thread(
                        target=self._handle_admin_connection, 
                        args=(conn, addr, log_ctx_admin_conn), 
                        name=f"AdminClient-{addr[0]}-{addr[1]}",
                        daemon=True 
                    )
                    self.admin_handling_threads.append(admin_client_thread)
                    admin_client_thread.start()
                elif self.shutdown_event.is_set(): 
                    break
        except Exception as e:
            if not self.shutdown_event.is_set(): 
                self.logger.critical("Error in admin accept loop.", exc_info=True)
        self.logger.info("Admin interface listener loop ended.")

    def _handle_admin_connection(self, conn, addr, log_ctx_admin_conn): 
        self.logger.info(f"Admin command connection started.", extra=log_ctx_admin_conn)
        response_payload = {"status": "error", "message": "Invalid admin command"}
        try:
            message = self.admin_sf_server._receive_message(conn) 
            if message and message.get("type") == "admin_command":
                command_payload = message.get("payload", {})
                command = command_payload.get("command")
                params = command_payload.get("params", {})
                log_ctx_admin_cmd = {**log_ctx_admin_conn, 'admin_command': command, 'admin_params': params}
                self.logger.info(f"Received admin command.", extra=log_ctx_admin_cmd)

                if command == "get_detailed_queue":
                    response_payload = self._handle_get_detailed_queue_command()
                elif command == "get_logs":
                    response_payload = self._handle_get_logs_command(params)
                elif command == "get_worker_status":
                    response_payload = self._handle_get_worker_status_command()
                elif command == "cancel_job":
                    response_payload = self._handle_cancel_job_command(params)
                elif command == "set_max_jobs":
                    response_payload = self._handle_set_max_jobs_command(params)
                else:
                    self.logger.warning(f"Unknown admin command received.", extra=log_ctx_admin_cmd)
                    response_payload = {"status": "error", "message": f"Unknown admin command: {command}"}
            else:
                self.logger.warning(f"Invalid message type from admin client.", extra={**log_ctx_admin_conn, 'received_message': message})
                response_payload = {"status": "error", "message": "Invalid message type for admin interface."}
        except Exception as e:
            self.logger.error(f"Error handling admin command.", exc_info=True, extra=log_ctx_admin_conn)
            response_payload = {"status": "error", "message": f"Server error processing admin command: {str(e)}"}
        finally:
            if self.admin_sf_server: 
                self.admin_sf_server._send_message(conn, "admin_response", response_payload) 
            if conn:
                conn.close()
            self.admin_handling_threads = [t for t in self.admin_handling_threads if t.is_alive()]
            self.logger.info("Admin connection closed.", extra=log_ctx_admin_conn)

    def _handle_get_detailed_queue_command(self):
        with self.job_queue.mutex:
            jobs_snapshot = [job for job in self.job_queue.queue if job]
        
        detailed_jobs = []
        for job_data in jobs_snapshot:
            details = {
                "job_id": job_data.get("job_id"),
                "status": job_data.get("status", "queued"),
                "primary_input_file_name": job_data.get("primary_input_file_name"),
                "num_input_files": job_data.get("num_input_files"),
                "submitted_at_utc": time.strftime("%Y-%m-%d %H:%M:%S UTC", time.gmtime(job_data.get("submitted_at"))),
                "job_input_dir_on_server": job_data.get("job_input_dir_on_server"),
                "client_recon_options": job_data.get("client_recon_options", {}),
            }
            detailed_jobs.append(details)
        self.logger.debug("Detailed job queue information retrieved for admin.", extra={'queue_count': len(detailed_jobs)})
        return {"status": "success", "queue": detailed_jobs, "count": len(detailed_jobs)}

    def _handle_get_logs_command(self, params: dict):
        num_lines = params.get("lines", 100) 
        job_id_filter = params.get("jobid")
        log_ctx = {'requested_lines': num_lines, 'job_id_filter': job_id_filter}
        
        if not self.log_filepath or not os.path.exists(self.log_filepath):
            self.logger.error("Log file path not configured or file does not exist.", extra=log_ctx)
            return {"status": "error", "message": "Log file not available."}
            
        log_entries = []
        try:
            with open(self.log_filepath, 'r') as lf:
                if job_id_filter:
                    job_id_search_str = f"\"job_id\": \"{job_id_filter}\"" 
                    all_lines = [line for line in lf if job_id_search_str in line]
                    log_entries = all_lines[-num_lines:]
                else:
                    all_lines = lf.readlines()
                    log_entries = all_lines[-num_lines:]
            self.logger.debug(f"Retrieved {len(log_entries)} log lines for admin.", extra=log_ctx)
            return {"status": "success", "logs": "".join(log_entries)}
        except Exception as e:
            self.logger.error(f"Error reading log file for admin.", exc_info=True, extra=log_ctx)
            return {"status": "error", "message": f"Could not read log file: {str(e)}"}

    def _handle_get_worker_status_command(self):
        current_statuses = self.worker_statuses.copy() 
        formatted_statuses = []
        for thread_id, info in current_statuses.items():
            thread_obj = next((t for t in self.worker_threads if t.ident == thread_id), None)
            status_detail = {
                "worker_name": info.get("name", f"Thread-{thread_id}"), # Use name from status dict
                "thread_id": thread_id,
                "status": info.get("status", "unknown"),
                "current_job_id": info.get("job_id"),
                "alive": thread_obj.is_alive() if thread_obj else False,
                "started_at_utc": time.strftime("%Y-%m-%d %H:%M:%S UTC", time.gmtime(info.get("started_at"))) if info.get("started_at") else "N/A"
            }
            formatted_statuses.append(status_detail)
        self.logger.debug("Worker status information retrieved for admin.", extra={'worker_count': len(formatted_statuses)})
        return {"status": "success", "workers": formatted_statuses}

    def _handle_cancel_job_command(self, params: dict):
        job_id_to_cancel = params.get("job_id")
        self.logger.info(f"ADMIN COMMAND: Received request to cancel job (not yet implemented).", extra={'requested_job_id_cancel': job_id_to_cancel, 'admin_command': 'cancel_job'})
        return {"status": "pending", "message": f"Cancel command for job {job_id_to_cancel} received, but feature not fully implemented."}

    def _handle_set_max_jobs_command(self, params: dict):
        new_max_jobs = params.get("count")
        self.logger.info(f"ADMIN COMMAND: Received request to set max_concurrent_jobs to {new_max_jobs} (not yet implemented).", extra={'requested_max_jobs': new_max_jobs, 'admin_command': 'set_max_jobs'})
        return {"status": "pending", "message": f"Set max_concurrent_jobs to {new_max_jobs} command received, but feature not fully implemented."}


    def run(self):
        self.logger.info("ReconServerApp starting.", extra={'max_concurrent_jobs': self.max_concurrent_jobs, 'listen_port': self.server_port})
        if not self.shared_key or self.shared_key == "SET_YOUR_SHARED_KEY_HERE":
            self.logger.critical("CRITICAL: Main SHARED_KEY is not set or is a placeholder. Client communication is insecure.", extra={'security_issue': 'invalid_main_shared_key'})

        if not self.sf_server.start(): 
            self.logger.critical("Main SecureFileTransferServer failed to start. Server cannot run.", extra={'server_type': 'main_client_facing'})
            return
        
        self.shutdown_event.clear()
        
        self.worker_threads = [] 
        for i in range(self.max_concurrent_jobs):
            thread = threading.Thread(target=self._job_worker_loop, name=f"Worker-{i+1}", daemon=True)
            self.worker_threads.append(thread) 
            thread.start()
        self.logger.info(f"Started {len(self.worker_threads)} worker thread(s). Listening on {self.server_hostname}:{self.server_port}.")

        if self.server_admin_shared_key and self.server_admin_port:
            self.admin_sf_server = SecureFileTransferServer(
                host=self.server_hostname, port=self.server_admin_port,
                shared_key=self.server_admin_shared_key, download_dir=None,
                logger=self.logger # Pass logger to admin server instance
            )
            if not self.admin_sf_server.start(): 
                self.logger.error("Admin interface SecureFileTransferServer failed to start. Continuing without admin interface.", extra={'admin_port': self.server_admin_port})
                self.admin_sf_server = None
            else:
                self.logger.info(f"Admin interface listening.", extra={'admin_host': self.server_hostname, 'admin_port': self.server_admin_port})
                self.admin_listener_thread = threading.Thread(target=self._admin_listener_loop, name="AdminListenerLoop", daemon=True)
                self.admin_listener_thread.start()
        else:
            self.logger.warning("Admin interface shared key or port not configured correctly. Admin interface will not be available.")

        try:
            while self.KEEPALIVE and not self.shutdown_event.is_set():
                conn, addr = self.sf_server.accept_connection() 
                if conn is None: 
                    if self.KEEPALIVE and not self.shutdown_event.is_set(): time.sleep(0.1) 
                    continue
                
                client_ip = addr[0]
                log_ctx_conn = {'client_ip': client_ip, 'client_port': addr[1]}
                if not self._validate_ip(client_ip): 
                    self.sf_server._send_message(conn, "error", {"message": "Untrusted IP."}) 
                    conn.close()
                    continue
                
                self.logger.info("Accepted new client connection.", extra=log_ctx_conn)
                client_handler_thread = threading.Thread(target=self._handle_client_connection, args=(conn, addr), name=f"ClientHandler-{client_ip}", daemon=True)
                client_handler_thread.start()
                
        except KeyboardInterrupt: 
            self.logger.info("KeyboardInterrupt received, initiating shutdown...")
        except Exception as e: 
            self.logger.critical("Main loop encountered an unexpected error.", exc_info=True)
        finally: 
            self.stop_server()

    def stop_server(self):
        if not self.KEEPALIVE and self.shutdown_event.is_set(): 
            self.logger.debug("Server stop already in progress or completed.")
            return
        self.logger.info("Initiating server shutdown...")
        self.KEEPALIVE = False; self.shutdown_event.set()
        
        if self.sf_server: 
            self.sf_server.stop()
        if self.admin_sf_server: 
            self.admin_sf_server.stop()

        for _ in range(len(self.worker_threads)): 
            try: self.job_queue.put(None, timeout=0.1) 
            except queue.Full: 
                self.logger.warning("Job queue full while trying to send shutdown signals to workers.")
                break 
        
        for t in self.worker_threads:
            if t.is_alive():
                try: t.join(timeout=1.0)
                except Exception as e: self.logger.error(f"Error joining worker thread {t.name}.", exc_info=True, extra={'thread_name': t.name})
        self.worker_threads = []
        
        if self.admin_listener_thread and self.admin_listener_thread.is_alive():
            try: self.admin_listener_thread.join(timeout=1.0)
            except Exception as e: self.logger.error(f"Error joining admin listener thread.", exc_info=True)
        
        active_admin_threads = [t for t in self.admin_handling_threads if t.is_alive()]
        for t in active_admin_threads:
            try: t.join(timeout=0.5)
            except Exception as e: self.logger.error(f"Error joining active admin handler thread {t.name}.", exc_info=True, extra={'thread_name': t.name})

        self.logger.info("Server shut down complete.")

if __name__ == "__main__":
    # Basic pre-logger print for this specific startup phase
    print(json.dumps({"timestamp": time.strftime('%Y-%m-%dT%H:%M:%S%z'), "level": "INFO", "name": "__main__", "message": "Application starting up..."}))
    opts_file = 'recon.opts'
    if not os.path.exists(opts_file):
        print(json.dumps({"timestamp": time.strftime('%Y-%m-%dT%H:%M:%S%z'), "level": "INFO", "name": "__main__", "message": f"'{opts_file}' not found. Creating default."}))
        try: 
            readoptions(opts_file) # This might print its own non-JSON messages
        except Exception as e: 
            print(json.dumps({"timestamp": time.strftime('%Y-%m-%dT%H:%M:%S%z'), "level": "CRITICAL", "name": "__main__", "message": f"ERROR creating default '{opts_file}': {e}", "error_details": str(e)}))
            sys.exit(1)
    
    app = None
    try: 
        app = ReconServerApp(options_file=opts_file)
        app.run()
    except Exception as e: 
        # If app.logger is set up, use it, otherwise print JSON
        logger_instance = getattr(app, 'logger', None)
        if logger_instance:
            logger_instance.critical("CRITICAL Top-Level Error during app instantiation or run.", exc_info=True, extra={'error_details': str(e)})
        else:
            print(json.dumps({"timestamp": time.strftime('%Y-%m-%dT%H:%M:%S%z'), "level": "CRITICAL", "name": "__main__", "message": f"CRITICAL Top-Level Error: {e}", "error_details": str(e), "traceback": traceback.format_exc()}))
    finally: 
        if app and (app.KEEPALIVE or not app.shutdown_event.is_set()): 
            app.stop_server()
        
        print(json.dumps({"timestamp": time.strftime('%Y-%m-%dT%H:%M:%S%z'), "level": "INFO", "name": "__main__", "message": "Application terminated."}))

```
