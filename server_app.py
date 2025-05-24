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

try:
    from reconlibs import readoptions
    from secure_transfer import SecureFileTransferServer
except ImportError as e:
    print(f"CRITICAL ERROR: Could not import modules: {e}. Ensure reconlibs.py and secure_transfer.py are in PYTHONPATH.")
    sys.exit(1)

class ReconServerApp:
    DEBUG = True 
    KEEPALIVE = True 

    def __init__(self, options_file: str = "recon.opts"):
        self.options_file = options_file
        self.server_hostname: str = "localhost"
        self.server_port: int = 60000
        self.shared_key: str = ""
        self.recon_server_base_pfile_dir: str = "/tmp/recon_server_pfiles"
        self.recon_script_path: str = "default_recon_script.sh"
        self.recon_server_dicom_output_dir: str = "/tmp/recon_server_dicoms" 
        self.log_filepath: str = "/tmp/recon_server.log"
        self.trusted_ips: list[str] = []
        self.max_concurrent_jobs: int = 1 
        self.start_time = time.time() # For uptime

        self._load_configuration()

        os.makedirs(self.recon_server_base_pfile_dir, exist_ok=True)
        os.makedirs(self.recon_server_dicom_output_dir, exist_ok=True)

        self.sf_server = SecureFileTransferServer(
            host=self.server_hostname,
            port=self.server_port,
            shared_key=self.shared_key,
            download_dir=self.recon_server_base_pfile_dir 
        )
        
        self.job_queue: queue.Queue = queue.Queue()
        self.shutdown_event = threading.Event()
        self.worker_threads: list[threading.Thread] = []
        
        self._log_message(f"ReconServerApp initialized. Max jobs: {self.max_concurrent_jobs}. Base PFILE dir: {self.recon_server_base_pfile_dir}", is_debug=False)
        if not self.shared_key or self.shared_key == "SET_YOUR_SHARED_KEY_HERE":
            self._log_message("CRITICAL WARNING: Shared key invalid. Communication insecure.", is_error=True)

    def _log_message(self, message: str, is_error: bool = False, is_debug: bool = False, client_addr: str | None = None, job_id: str | None = None):
        log_prefix = "[ServerApp] "
        if job_id: log_prefix += f"[Job:{job_id}] "
        if client_addr: log_prefix += f"[{client_addr}] "
        log_entry = f"[{time.asctime()}] {log_prefix}{message}"

        if is_error: print(f"ERROR: {log_entry}")
        elif is_debug and not self.DEBUG: return
        else: print(log_entry)
        
        try:
            with open(self.log_filepath, 'a') as lf: lf.write(log_entry + "\n")
        except IOError as e: print(f"Warning: Could not write to log file {self.log_filepath}: {e}")

    def _load_configuration(self):
        self._log_message(f"Loading configuration from '{self.options_file}'...", is_debug=True)
        try:
            config_tuple = readoptions(self.options_file)
            self.server_hostname, self.server_port = config_tuple[0], int(config_tuple[1])
            self.recon_server_base_pfile_dir, self.recon_script_path = config_tuple[6], config_tuple[7]
            self.recon_server_dicom_output_dir, self.log_filepath = config_tuple[8], config_tuple[10]
            self.shared_key, self.max_concurrent_jobs = config_tuple[11], int(config_tuple[12])
            misc_options_lines = config_tuple[13]

            if self.max_concurrent_jobs <= 0:
                self._log_message(f"MAX_CONCURRENT_JOBS must be positive. Defaulting to 1.", is_error=True)
                self.max_concurrent_jobs = 1
            
            self.trusted_ips = [] 
            for line in misc_options_lines:
                line_upper = line.strip().upper()
                if line_upper.startswith("#TRUSTEDIPS:") or (line_upper.startswith("TRUSTEDIPS:") and not line_upper.startswith("#")):
                    ips_str = line.split(":", 1)[1].strip()
                    if ips_str: self.trusted_ips = [ip.strip() for ip in ips_str.split(',') if ip.strip()]
                    break
            self._log_message(f"Config: Max Jobs = {self.max_concurrent_jobs}", is_debug=True)
        except Exception as e: self._log_message(f"CRITICAL: Error loading/parsing config: {e}", is_error=True); traceback.print_exc(); raise
    
    def _validate_ip(self, client_ip: str) -> bool:
        if not self.trusted_ips: return True
        if client_ip in self.trusted_ips: return True
        self._log_message(f"IP {client_ip} NOT trusted. Denying.", is_error=True, client_addr=client_ip)
        return False

    def _trigger_external_script(self, input_path_or_dir: str, client_options_dict: dict | None = None, job_id: str | None = None) -> bool:
        script_to_execute = self.recon_script_path
        self._log_message(f"Triggering script '{script_to_execute}' for Input: '{input_path_or_dir}'. Options: {client_options_dict}", job_id=job_id, is_debug=True)
        command = []
        if script_to_execute.lower().endswith('.py'):
            command = ["python", script_to_execute, input_path_or_dir] 
            if client_options_dict:
                for key, value in client_options_dict.items(): command.extend([f"--{key.replace('_', '-')}", str(value)])
        elif script_to_execute.lower().endswith('.m'):
            func = os.path.splitext(os.path.basename(script_to_execute))[0]
            args = f"'{input_path_or_dir}'"
            if client_options_dict:
                for k, v in client_options_dict.items(): args += f",'{k}','{str(v)}'"
            matlab_cmd = f"try; {func}({args}); catch e; disp(e.message); exit(1); end; exit(0);"
            command = ["matlab", "-batch", matlab_cmd] # Use -batch for non-interactive execution
        else: 
            command = [script_to_execute, input_path_or_dir]
            if client_options_dict:
                for k, v in client_options_dict.items(): command.extend([f"--{k.replace('_', '-')}", str(v)])
        
        self._log_message(f"Executing: {' '.join(command)}", job_id=job_id, is_debug=True)
        script_dir = os.path.dirname(script_to_execute) if os.path.isabs(script_to_execute) else None
        try:
            process = subprocess.run(command, cwd=script_dir, capture_output=True, text=True, check=False, timeout=1800) # 30 min timeout
            log_level_debug = process.returncode == 0
            self._log_message(f"Script for {input_path_or_dir} ended. RC:{process.returncode}", job_id=job_id, is_debug=log_level_debug, is_error=not log_level_debug)
            if process.stdout: self._log_message(f"STDOUT:\n{process.stdout}", job_id=job_id, is_debug=log_level_debug, is_error=not log_level_debug and bool(process.stdout.strip()))
            if process.stderr: self._log_message(f"STDERR:\n{process.stderr}", job_id=job_id, is_error=True) 
            return process.returncode == 0
        except Exception as e: self._log_message(f"Exception running {script_to_execute}: {e}", job_id=job_id, is_error=True); traceback.print_exc(); return False

    def _handle_get_server_status(self, conn: socket.socket, client_addr_ip: str):
        self._log_message("Handling 'get_server_status' command.", client_addr=client_addr_ip, is_debug=True)
        uptime_seconds = time.time() - self.start_time
        uptime_formatted = time.strftime("%Hh %Mm %Ss", time.gmtime(uptime_seconds))
        payload = {
            "server_uptime": uptime_formatted,
            "configured_max_workers": self.max_concurrent_jobs,
            "current_worker_thread_count": len(self.worker_threads), 
            "queued_jobs_in_system": self.job_queue.qsize() 
        }
        self.sf_server.send_command_to_client(conn, "server_status_response", payload)

    def _handle_get_queue_details(self, conn: socket.socket, client_addr_ip: str):
        self._log_message("Handling 'get_queue_details' command.", client_addr=client_addr_ip, is_debug=True)
        with self.job_queue.mutex: 
            jobs_snapshot = list(self.job_queue.queue)
        
        job_details_list = []
        for job_item in jobs_snapshot:
            if job_item: 
                submit_time_formatted = time.strftime("%Y-%m-%d %H:%M:%S UTC", time.gmtime(job_item.get('submitted_at', 0)))
                job_details_list.append({
                    "job_id": job_item.get('job_id', 'N/A'),
                    "status": job_item.get('status', 'queued'), 
                    "primary_input_file": job_item.get('primary_input_file_name', 'N/A'),
                    "num_input_files": job_item.get('num_input_files', 0),
                    "submitted_at_utc": submit_time_formatted,
                    "job_input_dir_basename": os.path.basename(job_item.get('job_input_dir_on_server','N/A'))
                })
        payload = {"jobs": job_details_list, "count": len(job_details_list)}
        self.sf_server.send_command_to_client(conn, "queue_details_response", payload)

    def _handle_client_connection(self, conn: socket.socket, client_addr_tuple: tuple[str, int]):
        client_ip = client_addr_tuple[0]
        job_id_for_recon_job = None 
        job_input_dir_for_recon_job = None
        command_name_for_finally = "Unknown"
        
        try:
            self._log_message("Waiting for initial command from client.", client_addr=client_ip, is_debug=True)
            initial_message = self.sf_server._receive_message(conn)

            if not initial_message:
                self._log_message("No initial message/client disconnected.", client_addr=client_ip, is_error=True); conn.close(); return

            msg_type = initial_message.get("type")
            payload = initial_message.get("payload", {})
            
            if msg_type != "command":
                self._log_message(f"Expected 'command' type, got '{msg_type}'.", client_addr=client_ip, is_error=True); conn.close(); return

            command_name = payload.get("command_name")
            command_name_for_finally = command_name or "Unknown"
            
            current_job_id_log = None
            if command_name == "submit_recon_job":
                job_id_for_recon_job = str(uuid.uuid4())
                job_input_dir_for_recon_job = os.path.join(self.recon_server_base_pfile_dir, f"job_{job_id_for_recon_job}_input")
                current_job_id_log = job_id_for_recon_job
            
            self._log_message(f"Received command: {command_name}", client_addr=client_ip, job_id=current_job_id_log)

            if command_name == "get_server_status":
                self._handle_get_server_status(conn, client_ip); conn.close(); return
            elif command_name == "get_queue_details":
                self._handle_get_queue_details(conn, client_ip); conn.close(); return
            elif command_name == "submit_recon_job":
                self._log_message("Processing 'submit_recon_job'.", client_addr=client_ip, job_id=job_id_for_recon_job, is_debug=True)

                client_files_payload = payload.get('files')
                options_json = payload.get("client_recon_options_json", "{}")
                client_recon_options = json.loads(options_json) if isinstance(options_json, str) else {}

                if not client_files_payload or not isinstance(client_files_payload, list):
                    self._log_message("Invalid 'files' list in submit_recon_job.", client_addr=client_ip, job_id=job_id_for_recon_job, is_error=True)
                    self.sf_server.send_command_to_client(conn, "error", {"message": "Job submission: 'files' list missing/malformed."}); conn.close(); return
                
                os.makedirs(job_input_dir_for_recon_job, exist_ok=True)
                received_paths = []
                for file_info in client_files_payload:
                    original_path = file_info.get('original_path_on_client')
                    expected_name = os.path.basename(file_info.get('name', f"file_{uuid.uuid4().hex[:8]}"))
                    if not original_path: raise ValueError(f"Missing original_path for {expected_name}")

                    if not self.sf_server.request_file_from_client(conn, original_path):
                        raise ConnectionAbortedError(f"Failed to send 'request_file' for {original_path}")
                    
                    received_path = self.sf_server.receive_file_securely(conn, expected_filename=expected_name, save_dir_override=job_input_dir_for_recon_job)
                    if not received_path: raise ConnectionAbortedError(f"Failed receiving {expected_name}")
                    received_paths.append(received_path)
                
                primary_file = os.path.basename(received_paths[0]) if received_paths else None
                job_data = {
                    "job_id": job_id_for_recon_job, "job_input_dir_on_server": job_input_dir_for_recon_job,
                    "num_input_files": len(received_paths), "primary_input_file_name": primary_file,
                    "client_recon_options": client_recon_options, "client_conn": conn, 
                    "client_addr_tuple": client_addr_tuple, "submitted_at": time.time(), "status": "queued"
                }
                self.job_queue.put(job_data)
                self._log_message(f"Job {job_id_for_recon_job} with {len(received_paths)} file(s) queued.", client_addr=client_ip, job_id=job_id_for_recon_job)
                self.sf_server.send_command_to_client(conn, "job_queued", {"job_id": job_id_for_recon_job, "num_files_received": len(received_paths)})
            else:
                self._log_message(f"Unknown command: {command_name}", client_addr=client_ip, is_error=True)
                self.sf_server.send_command_to_client(conn, "error", {"message": f"Unknown command: {command_name}"}); conn.close()
        
        except (socket.error, json.JSONDecodeError, ConnectionAbortedError, ValueError) as e:
            active_job_id = job_id_for_recon_job if command_name_for_finally == "submit_recon_job" else None 
            self._log_message(f"Client handling error ({command_name_for_finally}): {e}", client_addr=client_ip, job_id=active_job_id, is_error=True)
            if command_name_for_finally == "submit_recon_job" and job_input_dir_for_recon_job and os.path.isdir(job_input_dir_for_recon_job): 
                shutil.rmtree(job_input_dir_for_recon_job, ignore_errors=True)
            if conn: conn.close()
            if conn in self.sf_server.client_connections: del self.sf_server.client_connections[conn]
        except Exception as e:
            active_job_id = job_id_for_recon_job if command_name_for_finally == "submit_recon_job" else None
            self._log_message(f"Unexpected critical error with client {client_ip} ({command_name_for_finally}): {e}", client_addr=client_ip, job_id=active_job_id, is_error=True)
            traceback.print_exc()
            if command_name_for_finally == "submit_recon_job" and job_input_dir_for_recon_job and os.path.isdir(job_input_dir_for_recon_job): 
                shutil.rmtree(job_input_dir_for_recon_job, ignore_errors=True)
            if conn: 
                try: self.sf_server._send_message(conn, "error", {"message": f"Unexpected server error: {str(e)}"})
                except: pass
                conn.close()
            if conn in self.sf_server.client_connections: del self.sf_server.client_connections[conn]

    def _job_worker_loop(self):
        worker_name = threading.current_thread().name
        self._log_message(f"{worker_name} started.", is_debug=True)
        while not self.shutdown_event.is_set():
            job = None; conn_to_client = None; job_id = "N/A"; client_ip = "N/A"; job_input_dir = None
            try:
                job = self.job_queue.get(timeout=1)
                if job is None: self.job_queue.task_done(); break

                job_id = job["job_id"]; job["status"] = "processing" 
                conn_to_client = job["client_conn"]; client_ip = job["client_addr_tuple"][0]
                job_input_dir = job['job_input_dir_on_server']
                primary_file_name = job.get("primary_input_file_name", "N/A")
                
                self._log_message(f"Processing job for input {job_input_dir}", client_addr=client_ip, job_id=job_id)
                success = self._trigger_external_script(job_input_dir, job['client_recon_options'], job_id=job_id)
                
                dicom_dir_for_job = self.recon_server_dicom_output_dir 
                
                if success:
                    dicoms = [f for f in os.listdir(dicom_dir_for_job) if os.path.isfile(os.path.join(dicom_dir_for_job, f))] 
                    
                    if not dicoms:
                        self.sf_server.send_command_to_client(conn_to_client, "recon_status", {"job_id": job_id, "status": "completed_no_dicoms", "pfile": primary_file_name})
                    else:
                        ack_dicom_start = self.sf_server.send_command_to_client(conn_to_client, "dicom_transfer_start", {"job_id": job_id, "num_files": len(dicoms)})
                        if ack_dicom_start and ack_dicom_start.get("status") == "ready":
                            for d_name in dicoms:
                                if not self.sf_server.send_file_to_client(conn_to_client, os.path.join(dicom_dir_for_job, d_name)): break
                        else:
                             self._log_message(f"Client not ready for DICOMs for job {job_id}. Ack: {ack_dicom_start}", client_addr=client_ip, job_id=job_id, is_error=True)
                    self.sf_server.send_command_to_client(conn_to_client, "recon_complete", {"job_id": job_id, "pfile": primary_file_name})
                else:
                    self.sf_server.send_command_to_client(conn_to_client, "job_failed", {"job_id": job_id, "pfile": primary_file_name, "error": "Script failed."})
            
            except socket.error as e: self._log_message(f"Worker socket error: {e}", client_addr=client_ip, job_id=job_id, is_error=True)
            except Exception as e: 
                self._log_message(f"Worker error: {e}", client_addr=client_ip, job_id=job_id, is_error=True); traceback.print_exc()
                if conn_to_client:
                    try: self.sf_server.send_command_to_client(conn_to_client, "job_failed", {"job_id": job_id, "pfile": job.get("primary_input_file_name","N/A") if job else "N/A", "error": str(e)})
                    except: pass 
            finally:
                if job: self.job_queue.task_done()
                if conn_to_client: 
                    try: conn_to_client.close()
                    except: pass
                    if conn_to_client in self.sf_server.client_connections: del self.sf_server.client_connections[conn_to_client]
                if job_input_dir and os.path.isdir(job_input_dir): 
                    self._log_message(f"Cleaning up job input dir: {job_input_dir}", job_id=job_id, is_debug=True)
                    shutil.rmtree(job_input_dir, ignore_errors=True)
            
            except queue.Empty: continue
        self._log_message(f"{worker_name} shutting down.", is_debug=True)

    def run(self):
        if not self.sf_server.start(): self._log_message("Server failed to start.", is_error=True); return
        self.shutdown_event.clear()
        for i in range(self.max_concurrent_jobs):
            thread = threading.Thread(target=self._job_worker_loop, name=f"Worker-{i+1}", daemon=True)
            thread.start(); self.worker_threads.append(thread)
        self._log_message(f"Listening on {self.server_hostname}:{self.server_port} with {self.max_concurrent_jobs} worker(s).")

        try:
            while self.KEEPALIVE and not self.shutdown_event.is_set():
                conn, addr = self.sf_server.accept_connection()
                if conn is None: 
                    if self.KEEPALIVE and not self.shutdown_event.is_set(): time.sleep(0.1)
                    continue
                
                client_ip = addr[0]
                if not self._validate_ip(client_ip):
                    self.sf_server._send_message(conn, "error", {"message": "Untrusted IP."}); conn.close()
                    if conn in self.sf_server.client_connections: del self.sf_server.client_connections[conn]
                    continue
                
                client_handler_thread = threading.Thread(target=self._handle_client_connection, args=(conn, addr), daemon=True)
                client_handler_thread.start()
                
        except KeyboardInterrupt: self._log_message("KeyboardInterrupt received, shutting down...", is_debug=False)
        except Exception as e: self._log_message(f"Main loop error: {e}", is_error=True); traceback.print_exc()
        finally: self.stop_server()

    def stop_server(self):
        if not self.KEEPALIVE and self.shutdown_event.is_set(): return
        self._log_message("Initiating server shutdown...", is_debug=False)
        self.KEEPALIVE = False; self.shutdown_event.set()
        if self.sf_server: self.sf_server.stop()
        for _ in self.worker_threads:
            try: self.job_queue.put(None, timeout=0.1)
            except queue.Full: pass
        for t in self.worker_threads:
            try: t.join(timeout=1.0); 
            except Exception as e: self._log_message(f"Error joining {t.name}: {e}", is_error=True)
        self.worker_threads = []
        self._log_message("Server shut down.", is_debug=False)

if __name__ == "__main__":
    opts_file = 'recon.opts'
    if not os.path.exists(opts_file):
        print(f"INFO: '{opts_file}' not found. Creating default.")
        try: readoptions(opts_file) 
        except Exception as e: print(f"ERROR creating default '{opts_file}': {e}"); sys.exit(1)
    
    app = None
    try: app = ReconServerApp(options_file=opts_file); app.run()
    except Exception as e: print(f"CRITICAL Top-Level Error: {e}"); traceback.print_exc()
    finally: 
        if app and (app.KEEPALIVE or not app.shutdown_event.is_set()): app.stop_server()
        print("Application terminated.")

```
