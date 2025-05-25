import logging
import os
import sys
import time
import threading # For handling multiple client connections and health checks

try:
    from reconlibs import readoptions, generate_key
    from secure_transfer import SecureFileTransferServer, SecureFileTransferClient # Client for backend communication
except ImportError:
    print("CRITICAL ERROR: Could not import necessary modules. Ensure reconlibs.py and secure_transfer.py are in PYTHONPATH.")
    sys.exit(1)

# Global variable for the configuration dictionary, loaded in main()
RELAY_CONFIG = {}
logger = logging.getLogger(__name__) # Define logger at module level

def setup_logging():
    """Sets up logging for the relay server."""
    log_filepath = RELAY_CONFIG.get('LOG_FILEPATH', '/tmp/relay_server.log')
    log_level_str = RELAY_CONFIG.get('LOG_LEVEL', 'INFO').upper()
    debug_mode = RELAY_CONFIG.get('DEBUG', False) # Allow a DEBUG key in config

    if debug_mode and log_level_str == 'INFO': # If DEBUG=true, override to DEBUG level unless explicitly set otherwise
        log_level = logging.DEBUG
    else:
        log_level = getattr(logging, log_level_str, logging.INFO)

    logging.basicConfig(
        level=log_level,
        format='%(asctime)s - %(name)s - %(levelname)s - %(threadName)s - %(message)s',
        handlers=[
            logging.StreamHandler(sys.stdout)
        ]
    )
    
    # Add file handler if LOG_FILEPATH is specified and path is writable
    if log_filepath:
        try:
            # Ensure directory for log file exists
            log_dir = os.path.dirname(log_filepath)
            if log_dir and not os.path.exists(log_dir):
                os.makedirs(log_dir, exist_ok=True)
            
            file_handler = logging.FileHandler(log_filepath)
            file_handler.setFormatter(logging.Formatter('%(asctime)s - %(name)s - %(levelname)s - %(threadName)s - %(message)s'))
            logging.getLogger().addHandler(file_handler)
            logger.info(f"Logging to console and file: {log_filepath} at level {logging.getLevelName(log_level)}")
        except Exception as e:
            logger.error(f"Failed to set up file logging to {log_filepath}: {e}", exc_info=True)
            logger.info(f"Logging to console only at level {logging.getLevelName(log_level)}")
    else:
        logger.info(f"Logging to console only at level {logging.getLevelName(log_level)}")


class RelayServerApp:
    def __init__(self, config):
        self.config = config
        self.logger = logging.getLogger(self.__class__.__name__) # Class-specific logger
        self.sf_server = None
        self.shutdown_event = threading.Event()
        self.health_check_thread = None
        self.backend_servers_list = [] # Parsed list of (host, port, SecureFileTransferClient instance)
        self.current_backend_index = 0 # For round-robin

    def _parse_backend_servers(self):
        """Parses the BACKEND_SERVERS string into a list of tuples."""
        backend_servers_str = self.config.get('BACKEND_SERVERS', '')
        if not backend_servers_str:
            self.logger.error("No backend servers configured (BACKEND_SERVERS is empty). Relay cannot function.")
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
                self.logger.error(f"Invalid backend server entry format: '{s_entry}'. Expected host:port. Skipping.")
        
        if not servers:
            self.logger.error("No valid backend servers found after parsing BACKEND_SERVERS. Relay cannot function.")
            return False
            
        self.backend_servers_list = servers
        self.logger.info(f"Parsed backend servers: {[s['name'] for s in self.backend_servers_list]}")
        return True

    def start(self):
        self.logger.info("Starting Relay Server...")
        if not self._parse_backend_servers():
             self.logger.critical("Failed to parse backend server configuration. Shutting down.")
             return False # Indicate failure to start

        relay_hostname = self.config.get('RELAY_HOSTNAME', 'localhost')
        relay_port_str = self.config.get('RELAY_PORT', '60001')
        shared_key = self.config.get('SHARED_KEY_RELAY_TO_CLIENTS', 'SET_YOUR_RELAY_TO_CLIENTS_KEY_HERE')
        
        if shared_key == 'SET_YOUR_RELAY_TO_CLIENTS_KEY_HERE' or not shared_key:
            self.logger.critical("SHARED_KEY_RELAY_TO_CLIENTS is not set or is a placeholder. Server cannot start securely.")
            return False

        try:
            relay_port = int(relay_port_str)
        except ValueError:
            self.logger.critical(f"Invalid RELAY_PORT: {relay_port_str}. Must be an integer.")
            return False

        # Initialize SecureFileTransferServer for incoming client connections
        self.sf_server = SecureFileTransferServer(
            host=relay_hostname,
            port=relay_port,
            shared_key=shared_key,
            download_dir=self.config.get('RELAY_TEMP_DIR', '/tmp/relay_temp') # Relay might need a temp dir
        )
        
        if not self.sf_server.start():
            self.logger.error("Relay server failed to start SecureFileTransferServer for client connections.")
            return False

        self.logger.info(f"Relay server listening on {relay_hostname}:{relay_port}")

        # Start health check thread
        self.health_check_thread = threading.Thread(target=self._health_check_loop, name="HealthCheckThread", daemon=True)
        self.health_check_thread.start()

        # Main loop to accept client connections
        try:
            while not self.shutdown_event.is_set():
                conn, addr = self.sf_server.accept_connection()
                if conn:
                    self.logger.info(f"Accepted connection from {addr}")
                    client_thread = threading.Thread(target=self.handle_client_connection, args=(conn, addr), name=f"Client-{addr[0]}-{addr[1]}", daemon=True)
                    client_thread.start()
                elif self.shutdown_event.is_set():
                    break # Exit loop if shutdown is requested
        except Exception as e:
            self.logger.error(f"Error in main accept loop: {e}", exc_info=True)
        
        return True # Successfully started (even if main loop exits later)

    def stop(self):
        self.logger.info("Stopping Relay Server...")
        self.shutdown_event.set() # Signal all loops to stop
        if self.sf_server:
            self.sf_server.stop()
        if self.health_check_thread and self.health_check_thread.is_alive():
            self.health_check_thread.join(timeout=5)
        self.logger.info("Relay Server stopped.")

    def _health_check_loop(self):
        """Periodically checks the health of backend servers."""
        health_check_interval = int(self.config.get('HEALTH_CHECK_INTERVAL', 30)) # Default 30s
        self.logger.info(f"Health check loop started. Interval: {health_check_interval}s")
        while not self.shutdown_event.wait(health_check_interval): # Wait for interval or shutdown
            self.perform_health_checks()
        self.logger.info("Health check loop stopped.")

    def handle_client_connection(self, conn, addr):
        client_ip = addr[0]
        self.logger.info(f"Handling connection from {client_ip}:{addr[1]}")

        try:
            # 1. Access Control Check
            if not self.check_access_control(client_ip):
                self.logger.warning(f"Access denied for {client_ip}. Closing connection.")
                # Optionally send an error message to client before closing
                # self.sf_server.send_command_to_client(conn, "error", {"message": "Access denied: Untrusted IP."})
                return # Connection closed by SecureFileTransferServer if IP not in its list (if that feature is used)

            # 2. Receive client request (example: expecting a command)
            # This part is highly dependent on the protocol agreed with the client.
            # For now, assume we're just relaying raw data or simple commands.
            # initial_client_message = self.sf_server._receive_message(conn) # Using internal method for example
            # if not initial_client_message:
            #     self.logger.warning(f"No initial message from {client_ip}. Closing.")
            #     return
            # self.logger.debug(f"Received from client {client_ip}: {initial_client_message}")

            # 3. Select backend server (Load Balancing)
            backend_server_info = self.select_backend_server()
            if not backend_server_info:
                self.logger.error(f"No healthy backend server available for {client_ip}. Closing.")
                # self.sf_server.send_command_to_client(conn, "error", {"message": "No backend server available."})
                return
            
            self.logger.info(f"Selected backend {backend_server_info['name']} for client {client_ip}")

            # 4. Forward request to backend
            # This would involve:
            #   - Establishing a connection to the backend (or using an existing one)
            #   - Sending the client's request data
            #   - This needs a SecureFileTransferClient instance for each backend.
            #   - For simplicity, this placeholder won't implement the full forwarding.
            self.logger.debug(f"Placeholder: Would forward client's request to {backend_server_info['name']}")
            
            # Example: Send a dummy success message back to client
            # self.sf_server.send_command_to_client(conn, "success", {"message": f"Request relayed to {backend_server_info['name']}"})


            # 5. Relay response from backend to client
            # This would involve:
            #   - Receiving data from the backend
            #   - Sending that data back to the original client
            self.logger.debug(f"Placeholder: Would relay response from {backend_server_info['name']} to client {client_ip}")

        except Exception as e:
            self.logger.error(f"Error handling client {client_ip}: {e}", exc_info=True)
        finally:
            if conn:
                conn.close()
            self.logger.info(f"Connection with {client_ip}:{addr[1]} closed.")

    def check_access_control(self, client_ip: str) -> bool:
        """Checks if the client IP is allowed to connect."""
        trusted_ips_str = self.config.get('TRUSTED_CLIENT_IPS', '')
        if not trusted_ips_str: # If empty, allow all (default behavior)
            self.logger.debug(f"TRUSTED_CLIENT_IPS not set or empty. Allowing access for {client_ip}.")
            return True
        
        # Basic comma-separated IP list check. CIDR/range checks would need a library.
        trusted_ips_list = [ip.strip() for ip in trusted_ips_str.split(',') if ip.strip()]
        
        if client_ip in trusted_ips_list:
            self.logger.info(f"Access granted for trusted IP: {client_ip}")
            return True
        else:
            # Placeholder for CIDR checks if needed later
            # For now, direct match or full deny if list is present and IP not in it.
            self.logger.warning(f"Access denied for IP: {client_ip}. Not in TRUSTED_CLIENT_IPS list: {trusted_ips_list}")
            return False

    def perform_health_checks(self):
        """Performs health checks on all configured backend servers."""
        self.logger.info("Performing health checks on backend servers...")
        # This is a simplified health check. A real one might try a lightweight operation.
        for server_info in self.backend_servers_list:
            try:
                # For a real health check, you'd connect and maybe send a 'ping' or 'status' command
                # For now, just log the attempt.
                # If using SecureFileTransferClient for backend, it would need its own key.
                # This placeholder assumes a simple socket connection for health check.
                with socket.create_connection((server_info['host'], server_info['port']), timeout=5):
                    server_info['healthy'] = True
                    self.logger.info(f"Backend server {server_info['name']} is healthy.")
            except (socket.error, socket.timeout) as e:
                server_info['healthy'] = False
                self.logger.warning(f"Backend server {server_info['name']} is unhealthy: {e}")
        self.report_status() # Log current status after checks

    def report_status(self):
        """Reports the current status of the relay and its view of backend servers."""
        healthy_backends = [s['name'] for s in self.backend_servers_list if s['healthy']]
        unhealthy_backends = [s['name'] for s in self.backend_servers_list if not s['healthy']]
        self.logger.info(f"Relay Status: Running. Healthy Backends: {healthy_backends if healthy_backends else 'None'}. Unhealthy Backends: {unhealthy_backends if unhealthy_backends else 'None'}.")

    def select_backend_server(self) -> dict | None:
        """Selects a healthy backend server using round-robin."""
        if not self.backend_servers_list:
            self.logger.error("No backend servers configured to select from.")
            return None

        healthy_servers = [s for s in self.backend_servers_list if s['healthy']]
        if not healthy_servers:
            self.logger.error("No healthy backend servers available.")
            return None

        # Round-robin selection among healthy servers
        num_healthy = len(healthy_servers)
        selected_index = self.current_backend_index % num_healthy
        selected_server = healthy_servers[selected_index]
        
        self.current_backend_index = (self.current_backend_index + 1) % num_healthy
        
        self.logger.info(f"Selected backend server (round-robin): {selected_server['name']}")
        return selected_server

def main():
    global RELAY_CONFIG, logger # Make logger accessible if needed before class instantiation

    # Load configuration. readoptions will create 'relay.opts' with defaults if it doesn't exist.
    RELAY_CONFIG = readoptions('relay.opts') 
    
    # Setup logging based on the loaded (or default) configuration.
    setup_logging() 
    
    logger.info("Relay application starting...")
    if not RELAY_CONFIG: # Should not happen if readoptions works as expected
        logger.critical("Configuration could not be loaded. Exiting.")
        sys.exit(1)

    if RELAY_CONFIG.get('SHARED_KEY_RELAY_TO_CLIENTS', '') == 'SET_YOUR_RELAY_TO_CLIENTS_KEY_HERE' or \
       not RELAY_CONFIG.get('SHARED_KEY_RELAY_TO_CLIENTS'):
        logger.warning("CRITICAL SECURITY WARNING: SHARED_KEY_RELAY_TO_CLIENTS is not set or is using the default placeholder.")
        logger.warning("The server might be insecure. Please configure a strong shared key in relay.opts.")
        # For a production system, you might want to exit here:
        # logger.critical("Exiting due to insecure configuration.")
        # sys.exit(1)

    app = RelayServerApp(RELAY_CONFIG)
    try:
        if not app.start(): # Start also contains the main accept loop now
            logger.critical("Relay Server application failed to start properly. Exiting.")
            sys.exit(1)
        
        # The app.start() method now contains the blocking accept loop.
        # If it returns (e.g., on shutdown_event), the program will proceed to finally.
        # Kept for future use if start() becomes non-blocking:
        # while not app.shutdown_event.is_set():
        #     time.sleep(1) # Keep main thread alive while server runs

    except KeyboardInterrupt:
        logger.info("Relay Server shutting down due to KeyboardInterrupt.")
    except Exception as e:
        logger.critical(f"Relay Server failed with an unexpected error: {e}", exc_info=True)
    finally:
        if 'app' in locals() and app is not None:
            app.stop()
        logging.info("Relay Server application fully stopped.")

if __name__ == "__main__":
    main()
```
