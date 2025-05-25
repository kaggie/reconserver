import logging
import os
import sys
import time
import threading
import socket
import json
from pythonjsonlogger import jsonlogger # New import

try:
    from reconlibs import readoptions, generate_key
    from secure_transfer import SecureFileTransferServer, SecureFileTransferClient
except ImportError:
    # Basic print for critical startup error before logger is available
    print(json.dumps({
        "timestamp": time.strftime('%Y-%m-%dT%H:%M:%S%z'), "level": "CRITICAL", "name": __name__, 
        "message": f"Could not import necessary modules. Ensure reconlibs.py and secure_transfer.py are in PYTHONPATH."
    }))
    sys.exit(1)

RELAY_CONFIG = {}
# Logger will be configured in setup_logging, called from main()
# This initial logger is a placeholder until setup_logging is called.
logger = logging.getLogger(__name__) 
logger.addHandler(logging.NullHandler()) # Prevent "No handler found" warnings before setup

def setup_logging():
    """Sets up JSON logging for the relay server."""
    global logger # We are reconfiguring the module-level logger
    
    log_level_str = RELAY_CONFIG.get('LOG_LEVEL', 'INFO').upper()
    log_level = getattr(logging, log_level_str, logging.INFO)
    log_filepath = RELAY_CONFIG.get('LOG_FILEPATH', '/tmp/relay_server.log')

    # Re-initialize logger with the correct name for the application instance
    logger = logging.getLogger("RelayServerApp")
    logger.setLevel(log_level)
    logger.propagate = False # Avoid duplicate logs if root logger is also configured

    # Remove any existing handlers to prevent duplication if called multiple times
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
        self.config = config_dict # Use the already loaded config_dict
        self.logger = logging.getLogger(f"{__name__}.{self.__class__.__name__}") # Get child logger
        
        self.sf_server = None
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

        self._load_config() # Load specific attributes from self.config

    def _load_config(self):
        """Loads relay-specific configurations including admin settings."""
        self.logger.debug("Loading relay server configurations from provided dictionary.")
        self.relay_admin_port = int(self.config.get('RELAY_ADMIN_PORT', 60002))
        self.relay_admin_shared_key = self.config.get('RELAY_ADMIN_SHARED_KEY', '')
        
        admin_key_status = 'set'
        if not self.relay_admin_shared_key or self.relay_admin_shared_key == 'SET_YOUR_RELAY_ADMIN_KEY_HERE':
            self.logger.critical("RELAY_ADMIN_SHARED_KEY is not set or is a placeholder. Admin interface will NOT start.", extra={'security_issue': 'invalid_admin_key'})
            self.relay_admin_shared_key = "" 
            admin_key_status = 'not_set_or_placeholder'
        
        self.logger.info("Admin interface configuration loaded.", extra={'admin_port': self.relay_admin_port, 'admin_key_status': admin_key_status})
        
        if not self._parse_backend_servers():
             self.logger.critical("Failed to parse backend server configuration. Relay may not function correctly.")
             return False # Indicate failure
        return True


    def _parse_backend_servers(self):
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
                servers.append({'host': host, 'port': port, 'client': None, 'healthy': False, 'name': s_entry})
            except ValueError:
                self.logger.error(f"Invalid backend server entry format. Expected host:port.", extra={**log_ctx, 'invalid_entry': s_entry})
        
        if not servers:
            self.logger.error("No valid backend servers found after parsing BACKEND_SERVERS.", extra=log_ctx)
            return False
            
        self.backend_servers_list = servers
        self.logger.info(f"Parsed backend servers.", extra={**log_ctx, 'parsed_backend_names': [s['name'] for s in self.backend_servers_list]})
        return True

    def start(self):
        self.logger.info("Starting Relay Server application...")
        if not self._load_config(): # This now also calls _parse_backend_servers
             self.logger.critical("Failed to load critical configurations. Shutting down.")
             return False

        relay_hostname = self.config.get('RELAY_HOSTNAME', 'localhost')
        relay_port = int(self.config.get('RELAY_PORT', 60001)) # Assuming valid int from readoptions
        shared_key = self.config.get('SHARED_KEY_RELAY_TO_CLIENTS', '')
        
        start_ctx = {'relay_hostname': relay_hostname, 'relay_port': relay_port}
        if shared_key == 'SET_YOUR_RELAY_TO_CLIENTS_KEY_HERE' or not shared_key:
            self.logger.critical("SHARED_KEY_RELAY_TO_CLIENTS is not set or is a placeholder. Server cannot start securely.", extra={**start_ctx, 'security_issue': 'invalid_main_relay_key'})
            return False

        self.sf_server = SecureFileTransferServer(
            host=relay_hostname, port=relay_port, shared_key=shared_key,
            download_dir=self.config.get('RELAY_TEMP_DIR', '/tmp/relay_temp'),
            logger=self.logger.getChild("SFTServer.Main") # Pass child logger
        )
        
        if not self.sf_server.start():
            self.logger.error("Main SecureFileTransferServer failed to start for client connections.", extra=start_ctx)
            return False
        self.logger.info(f"Relay server listening for clients.", extra=start_ctx)

        if self.relay_admin_shared_key:
            self.admin_sf_server = SecureFileTransferServer(
                host=relay_hostname, port=self.relay_admin_port, shared_key=self.relay_admin_shared_key,
                download_dir=None, logger=self.logger.getChild("SFTServer.Admin")
            )
            if not self.admin_sf_server.start():
                self.logger.error(f"Relay admin interface failed to start. Continuing without admin interface.", extra={'admin_port': self.relay_admin_port})
                self.admin_sf_server = None
            else:
                self.logger.info(f"Relay admin interface listening.", extra={'admin_host': relay_hostname, 'admin_port': self.relay_admin_port})
                self.admin_listener_thread = threading.Thread(target=self._admin_listener_loop, name="AdminListenerThread", daemon=True)
                self.admin_listener_thread.start()
        else:
            self.logger.warning("Admin interface shared key not configured or invalid. Admin interface will not be available.")

        self.health_check_thread = threading.Thread(target=self._health_check_loop, name="HealthCheckThread", daemon=True)
        self.health_check_thread.start()

        try:
            while not self.shutdown_event.is_set():
                conn, addr = self.sf_server.accept_connection()
                if conn:
                    log_ctx_conn = {'client_ip': addr[0], 'client_port': addr[1], 'thread_name': threading.current_thread().name}
                    self.logger.info("Accepted new client connection.", extra=log_ctx_conn)
                    self.active_client_connections[addr] = {'connect_time': time.time(), 'ip': addr[0], 'port': addr[1]}
                    client_thread = threading.Thread(target=self.handle_client_connection, args=(conn, addr, log_ctx_conn), name=f"Client-{addr[0]}-{addr[1]}", daemon=True)
                    self.client_handling_threads.append(client_thread)
                    client_thread.start()
                elif self.shutdown_event.is_set(): break 
        except Exception as e:
            if not self.shutdown_event.is_set():
                 self.logger.critical("Error in main client accept loop.", exc_info=True)
        
        self.logger.info("Relay Server main client accept loop ended.")
        return True 

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
        
        for t in self.client_handling_threads:
            if t.is_alive(): threads_to_join.append(t)
        for t in self.admin_handling_threads:
            if t.is_alive(): threads_to_join.append(t)

        for t in threads_to_join:
            try:
                t.join(timeout=1.0) # Short timeout for each
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

    def handle_client_connection(self, conn, addr, log_ctx_conn): # Receive context
        self.logger.info("Handling new client connection.", extra=log_ctx_conn)
        try:
            if not self.check_access_control(addr[0]): # Pass only IP
                # check_access_control already logs denial
                return 

            # Placeholder for actual relay logic
            self.logger.debug("Placeholder: Client request received. Selecting backend.", extra=log_ctx_conn)
            backend_server_info = self.select_backend_server() # Logs internally
            if not backend_server_info:
                self.logger.error("No healthy backend server available for client.", extra=log_ctx_conn)
                # self.sf_server.send_command_to_client(conn, "error", {"message": "No backend server available."}) # Needs logging update in SFTServer
                return
            
            self.logger.debug("Placeholder: Forwarding client request to backend.", extra={**log_ctx_conn, 'selected_backend': backend_server_info.get('name')})
            # ... (actual relay logic for data transfer) ...
            self.logger.debug("Placeholder: Relaying response from backend to client.", extra={**log_ctx_conn, 'selected_backend': backend_server_info.get('name')})

        except Exception as e:
            self.logger.error("Error handling client connection.", exc_info=True, extra=log_ctx_conn)
        finally:
            if conn: conn.close()
            if addr in self.active_client_connections: # Use addr tuple as key
                del self.active_client_connections[addr]
            self.client_handling_threads = [t for t in self.client_handling_threads if t.is_alive()]
            self.logger.info("Client connection closed.", extra=log_ctx_conn)

    def handle_admin_command(self, conn, addr, log_ctx_admin_conn): # Receive context
        self.logger.info("Admin command connection started.", extra=log_ctx_admin_conn)
        response_payload = {"status": "error", "message": "Invalid admin command"}
        try:
            message = self.admin_sf_server._receive_message(conn)
            if message and message.get("type") == "admin_command":
                command_payload = message.get("payload", {})
                command = command_payload.get("command")
                log_ctx_admin_cmd = {**log_ctx_admin_conn, 'admin_command': command, 'admin_params': command_payload.get("params")}
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
        payload = {
            "status": "success", "relay_status": "running", "uptime": uptime_formatted,
            "connected_clients_count": len(self.active_client_connections),
            "active_client_handler_threads": len([t for t in self.client_handling_threads if t.is_alive()]),
            "active_admin_handler_threads": len([t for t in self.admin_handling_threads if t.is_alive()]),
            "backend_server_count": len(self.backend_servers_list)
        }
        self.logger.debug("Relay status command processed.", extra=payload)
        return payload

    def _handle_get_backend_health_command(self):
        backends_health = [{'name': b.get('name'), 'host': b.get('host'), 'port': b.get('port'), 'healthy': b.get('healthy', False)} for b in self.backend_servers_list]
        payload = {"status": "success", "backends": backends_health}
        self.logger.debug("Backend health command processed.", extra={'backends_count': len(backends_health)})
        return payload

    def _handle_get_connected_clients_command(self):
        clients_info = [{'ip_address': v['ip'], 'port': v['port'], 'connected_since_utc': time.strftime("%Y-%m-%d %H:%M:%S UTC", time.gmtime(v['connect_time'])), 'duration_seconds': int(time.time() - v['connect_time'])} for k, v in list(self.active_client_connections.items())]
        payload = {"status": "success", "clients": clients_info, "count": len(clients_info)}
        self.logger.debug("Connected clients command processed.", extra={'client_count': len(clients_info)})
        return payload

    def check_access_control(self, client_ip: str) -> bool:
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
        log_ctx_hc_start = {'thread_name': threading.current_thread().name}
        self.logger.info("Performing health checks on backend servers...", extra=log_ctx_hc_start)
        for server_info in self.backend_servers_list:
            backend_name = server_info.get('name', f"{server_info['host']}:{server_info['port']}")
            log_ctx_backend = {**log_ctx_hc_start, 'backend_name': backend_name, 'backend_host': server_info['host'], 'backend_port': server_info['port']}
            try:
                with socket.create_connection((server_info['host'], server_info['port']), timeout=5):
                    if not server_info.get('healthy'): # Log if status changed to healthy
                        self.logger.info(f"Backend server '{backend_name}' is now healthy.", extra=log_ctx_backend)
                    server_info['healthy'] = True
            except (socket.error, socket.timeout) as e:
                if server_info.get('healthy', True): # Log if status changed to unhealthy or was previously unknown but failed
                    self.logger.warning(f"Backend server '{backend_name}' is unhealthy.", extra={**log_ctx_backend, 'error_details': str(e)})
                server_info['healthy'] = False
        self.report_status()

    def report_status(self):
        healthy_backends = [s['name'] for s in self.backend_servers_list if s['healthy']]
        unhealthy_backends = [s['name'] for s in self.backend_servers_list if not s['healthy']]
        status_extra = {
            'healthy_backend_count': len(healthy_backends), 'unhealthy_backend_count': len(unhealthy_backends),
            'healthy_backends': healthy_backends, 'unhealthy_backends': unhealthy_backends,
            'connected_clients_count': len(self.active_client_connections)
        }
        self.logger.info("Relay server status report.", extra=status_extra)


    def select_backend_server(self) -> dict | None:
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
        
        self.logger.info(f"Selected backend server (round-robin).", extra={'selected_backend': selected_server['name'], 'selection_method': 'round_robin', 'healthy_server_count': num_healthy})
        return selected_server

def main():
    global RELAY_CONFIG, logger 

    # Initial basic print, as logger isn't fully set up until after readoptions.
    print(json.dumps({"timestamp": time.strftime('%Y-%m-%dT%H:%M:%S%z'), "level": "INFO", "name": "__main__", "message": "Relay application starting up..."}))
    
    opts_file = 'relay.opts'
    if not os.path.exists(opts_file):
        print(json.dumps({"timestamp": time.strftime('%Y-%m-%dT%H:%M:%S%z'), "level": "INFO", "name": "__main__", "message": f"'{opts_file}' not found. Creating default."}))
        try: readoptions(opts_file) 
        except Exception as e:
            print(json.dumps({"timestamp": time.strftime('%Y-%m-%dT%H:%M:%S%z'), "level": "CRITICAL", "name": "__main__", "message": f"ERROR creating default '{opts_file}': {e}", "error_details": str(e)}))
            sys.exit(1)
            
    RELAY_CONFIG = readoptions(opts_file) 
    setup_logging() # Now logger is fully configured.
    
    logger.info("Relay application starting with loaded configuration.", extra={'config_source': opts_file})
    if not RELAY_CONFIG:
        logger.critical("Configuration could not be loaded. Exiting.", extra={'config_source': opts_file})
        sys.exit(1)

    if RELAY_CONFIG.get('SHARED_KEY_RELAY_TO_CLIENTS', '') == 'SET_YOUR_RELAY_TO_CLIENTS_KEY_HERE' or \
       not RELAY_CONFIG.get('SHARED_KEY_RELAY_TO_CLIENTS'):
        logger.critical("CRITICAL SECURITY WARNING: SHARED_KEY_RELAY_TO_CLIENTS is not set or is using the default placeholder. Client-facing relay is insecure.", extra={'security_issue': 'invalid_main_relay_key'})

    app = None
    try:
        app = RelayServerApp(RELAY_CONFIG)
        if not app.start():
            logger.critical("Relay Server application failed to start properly. Exiting.")
            sys.exit(1)
        
        # Main thread will now effectively wait here or exit if start() fails or if it's non-blocking and there's no other loop.
        # For a server that runs indefinitely, start() would typically block or the main thread would enter its own loop.
        # Given the current structure of start(), it contains the main accept loop and will block.
        # If start() were non-blocking, a loop here like this would be needed:
        # while not app.shutdown_event.is_set():
        #    time.sleep(1) 

    except KeyboardInterrupt:
        logger.info("Relay Server shutting down due to KeyboardInterrupt.")
    except Exception as e:
        logger.critical("Relay Server failed with an unexpected error.", exc_info=True, extra={'error_details': str(e)})
    finally:
        if app is not None:
            app.stop()
        logger.info("Relay Server application fully stopped.")
        # Final print to console, as logger might be shut down or also terminating.
        print(json.dumps({"timestamp": time.strftime('%Y-%m-%dT%H:%M:%S%z'), "level": "INFO", "name": "__main__", "message": "Relay application terminated."}))


if __name__ == "__main__":
    main()
```
