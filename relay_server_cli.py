import argparse
import json
import os
import sys
import time # For potential use in formatting timestamps, etc.

# Ensure project root is in Python path for module imports
try:
    from secure_transfer import SecureFileTransferClient
    from reconlibs import readoptions
except ImportError:
    # This block allows the CLI to be run from anywhere if the project structure is consistent.
    # It assumes 'secure_transfer.py' and 'reconlibs.py' are in the parent directory if CLI is in a 'cli' subdir,
    # or in the same directory if all are flat. Adjust as needed.
    current_dir = os.path.dirname(os.path.abspath(__file__))
    project_root_path = os.path.dirname(current_dir) # Adjust if CLI is not one level down from project root
    if project_root_path not in sys.path:
        sys.path.insert(0, project_root_path)
    
    # Try importing again
    try:
        from secure_transfer import SecureFileTransferClient
        from reconlibs import readoptions
    except ImportError as e_inner:
        print(f"CRITICAL ERROR: Could not import necessary modules (secure_transfer, reconlibs): {e_inner}.")
        print("Ensure these modules are in your PYTHONPATH, or run the CLI from the project root, or adjust pathing in relay_server_cli.py.")
        sys.exit(1)

class RelayCLI:
    def __init__(self, config_path: str):
        try:
            self.config = readoptions(config_path)
        except FileNotFoundError:
            print(f"ERROR: Configuration file '{config_path}' not found.")
            sys.exit(1)
        except Exception as e:
            print(f"ERROR: Failed to read or parse configuration file '{config_path}': {e}")
            sys.exit(1)

        self.admin_host = self.config.get('RELAY_HOSTNAME', 'localhost') # Admin interface usually on same host as relay
        
        admin_port_val = self.config.get('RELAY_ADMIN_PORT', 60002)
        try:
            self.admin_port = int(admin_port_val)
        except ValueError:
            print(f"ERROR: Invalid RELAY_ADMIN_PORT '{admin_port_val}' in '{config_path}'. Must be an integer.")
            sys.exit(1)

        self.admin_shared_key = self.config.get('RELAY_ADMIN_SHARED_KEY')

        if not self.admin_shared_key or self.admin_shared_key == 'SET_YOUR_RELAY_ADMIN_KEY_HERE':
            print(f"ERROR: RELAY_ADMIN_SHARED_KEY is not set or is a placeholder in '{config_path}'.")
            print("Please generate a unique key and configure it in relay.opts for the admin interface.")
            sys.exit(1)

        self.client = SecureFileTransferClient(
            host=self.admin_host,
            port=self.admin_port,
            shared_key=self.admin_shared_key
        )
        # Set a timeout for client operations to prevent indefinite hanging
        self.client.timeout = 10 # seconds

    def _send_command(self, command_payload: dict) -> dict | None:
        print(f"Connecting to relay admin interface at {self.admin_host}:{self.admin_port}...")
        if not self.client.connect():
            print(f"Error: Could not connect to relay admin interface.")
            return None
        
        response_payload = None
        try:
            print(f"Sending command: {command_payload.get('command')}")
            # Using the specific send_command for clarity, assuming it exists or is similar to _send_message
            if not self.client.send_command("admin_command", command_payload): # CLI sends "admin_command" type
                print("Error: Failed to send command to relay admin interface.")
                return None
            
            # Wait for and receive the response
            print("Waiting for response...")
            response_message = self.client._receive_message() # Using _receive_message as per example
            
            if response_message and response_message.get("type") == "admin_response":
                response_payload = response_message.get("payload")
                print("Response received.")
            elif response_message:
                print(f"Error: Received unexpected message type '{response_message.get('type')}' from relay.")
                print(f"Full response: {response_message}")
            else:
                print("Error: No response or invalid response received from relay admin interface.")
            
        except ConnectionResetError:
            print("Error: Connection to relay admin interface was reset. Is the server running and key correct?")
        except Exception as e:
            print(f"An error occurred while communicating with the relay admin interface: {e}")
        finally:
            self.client.disconnect()
            print("Disconnected from relay admin interface.")
        
        return response_payload

    def get_status(self):
        payload = self._send_command({"command": "get_status"})
        if payload and payload.get('status') == 'success':
            print("\n--- Relay Server Status ---")
            print(f"  Relay Status: {payload.get('relay_status', 'N/A')}")
            print(f"  Uptime: {payload.get('uptime', 'N/A')}")
            print(f"  Connected Clients (Approx): {payload.get('connected_clients_count', 'N/A')}")
            print(f"  Active Client Handler Threads: {payload.get('active_client_handler_threads', 'N/A')}")
            print(f"  Active Admin Handler Threads: {payload.get('active_admin_handler_threads', 'N/A')}")
            print(f"  Configured Backend Servers: {payload.get('backend_server_count', 'N/A')}")
            print("---------------------------\n")
        elif payload:
            print(f"\nError from server: {payload.get('message', 'Unknown error')}\n")
        else:
            print("\nFailed to get status from server.\n")


    def get_backend_health(self):
        payload = self._send_command({"command": "get_backend_health"})
        if payload and payload.get('status') == 'success':
            backends = payload.get('backends', [])
            print("\n--- Backend Server Health ---")
            if backends:
                for backend in backends:
                    print(f"  Backend: {backend.get('name', f\"{backend.get('host')}:{backend.get('port')}\")}")
                    print(f"    Host: {backend.get('host', 'N/A')}")
                    print(f"    Port: {backend.get('port', 'N/A')}")
                    print(f"    Healthy: {'Yes' if backend.get('healthy') else 'No'}")
                    print("-" * 10)
            else:
                print("  No backend servers configured or reported.")
            print("---------------------------\n")
        elif payload:
            print(f"\nError from server: {payload.get('message', 'Unknown error')}\n")
        else:
            print("\nFailed to get backend health from server.\n")


    def get_connected_clients(self):
        payload = self._send_command({"command": "get_connected_clients"})
        if payload and payload.get('status') == 'success':
            clients = payload.get('clients', [])
            print("\n--- Connected Clients (Approximate) ---")
            if clients:
                for client_info in clients:
                    print(f"  Client IP: {client_info.get('ip_address')}")
                    print(f"    Connected Since (UTC): {client_info.get('connected_since_utc')}")
                    print(f"    Duration (s): {client_info.get('duration_seconds')}")
                    print("-" * 10)
            else:
                print("  No clients currently connected (or tracking not fully implemented on server for this view).")
            print(f"Total Connected Clients: {payload.get('count', 0)}")
            print("-------------------------------------\n")
        elif payload:
            print(f"\nError from server: {payload.get('message', 'Unknown error')}\n")
        else:
            print("\nFailed to get connected clients from server.\n")


def main():
    parser = argparse.ArgumentParser(
        description="Command-Line Interface for the Relay Server's Admin Port.",
        formatter_class=argparse.RawTextHelpFormatter
    )
    parser.add_argument(
        "--opts", 
        default="relay.opts", 
        help="Path to the relay.opts configuration file (default: relay.opts)"
    )
    
    subparsers = parser.add_subparsers(
        dest="command", 
        required=True,
        help="Available commands"
    )
    
    status_parser = subparsers.add_parser("status", help="Get the current status of the relay server.")
    backends_parser = subparsers.add_parser("backends", help="Get the health status of configured backend servers.")
    clients_parser = subparsers.add_parser("clients", help="List clients currently connected to the relay server (approximate).")
    # Add more subparsers here for future commands like 'stop'

    args = parser.parse_args()

    # Ensure options file exists before initializing CLI, or guide user
    if not os.path.exists(args.opts):
        print(f"ERROR: Relay options file '{args.opts}' not found.")
        # Try to create a default one using readoptions if it's available and supports it
        try:
            print(f"Attempting to create a default '{args.opts}' to guide configuration...")
            readoptions(args.opts) # This should create 'relay.opts' with defaults
            print(f"\nA default '{args.opts}' file has been created.")
            print("Please review and configure it, especially:")
            print("  - RELAY_HOSTNAME (if not localhost for admin access from this machine)")
            print("  - RELAY_ADMIN_PORT (if different from default 60002)")
            print("  - RELAY_ADMIN_SHARED_KEY (MUST be set to a secure, unique key)")
        except Exception as e:
            print(f"Could not create a default '{args.opts}': {e}")
        sys.exit(1)

    cli = None
    try:
        cli = RelayCLI(args.opts)
    except SystemExit: # Catch sys.exit from RelayCLI init if config is bad
        sys.exit(1) # Propagate exit
    except Exception as e: # Catch any other init errors
        print(f"Failed to initialize Relay CLI: {e}")
        sys.exit(1)


    if args.command == "status":
        cli.get_status()
    elif args.command == "backends":
        cli.get_backend_health()
    elif args.command == "clients":
        cli.get_connected_clients()
    # elif args.command == "stop":
    #     cli.stop_server() # Example for a future command
    else:
        print(f"Unknown command: {args.command}")
        parser.print_help()
        sys.exit(1)

if __name__ == "__main__":
    main()
```
