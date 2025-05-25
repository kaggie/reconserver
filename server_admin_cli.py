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
    current_dir = os.path.dirname(os.path.abspath(__file__))
    project_root_path = os.path.dirname(current_dir) 
    if project_root_path not in sys.path:
        sys.path.insert(0, project_root_path)
    try:
        from secure_transfer import SecureFileTransferClient
        from reconlibs import readoptions
    except ImportError as e_inner:
        print(f"CRITICAL ERROR: Could not import necessary modules (secure_transfer, reconlibs): {e_inner}.")
        print("Ensure these modules are in your PYTHONPATH, or run the CLI from the project root, or adjust pathing.")
        sys.exit(1)

class ServerAdminCLI:
    def __init__(self, config_path: str):
        try:
            self.config = readoptions(config_path) # Should be 'recon.opts'
        except FileNotFoundError:
            print(f"ERROR: Configuration file '{config_path}' not found.")
            sys.exit(1)
        except Exception as e:
            print(f"ERROR: Failed to read or parse configuration file '{config_path}': {e}")
            sys.exit(1)

        self.admin_host = self.config.get('SERVER_HOSTNAME', 'localhost') # Server admin on same host
        
        admin_port_val = self.config.get('SERVER_ADMIN_PORT', 60003)
        try:
            self.admin_port = int(admin_port_val)
        except ValueError:
            print(f"ERROR: Invalid SERVER_ADMIN_PORT '{admin_port_val}' in '{config_path}'. Must be an integer.")
            sys.exit(1)

        self.admin_shared_key = self.config.get('SERVER_ADMIN_SHARED_KEY')

        if not self.admin_shared_key or self.admin_shared_key == 'SET_YOUR_SERVER_ADMIN_KEY_HERE':
            print(f"ERROR: SERVER_ADMIN_SHARED_KEY is not set or is a placeholder in '{config_path}'.")
            print("Please generate a unique key and configure it in recon.opts for the server admin interface.")
            sys.exit(1)

        self.client = SecureFileTransferClient(
            host=self.admin_host,
            port=self.admin_port,
            shared_key=self.admin_shared_key
        )
        self.client.timeout = 10 # seconds for client operations

    def _send_admin_command(self, command: str, params: dict | None = None) -> dict | None:
        print(f"Connecting to server admin interface at {self.admin_host}:{self.admin_port}...")
        if not self.client.connect():
            print(f"Error: Could not connect to server admin interface.")
            return None
        
        response_payload = None
        try:
            command_payload = {"command": command}
            if params:
                command_payload["params"] = params
            
            print(f"Sending admin command: {command} with params: {params if params else '{}'}")
            if not self.client.send_command("admin_command", command_payload):
                print("Error: Failed to send command to server admin interface.")
                return None
            
            print("Waiting for response...")
            response_message = self.client._receive_message() 
            
            if response_message and response_message.get("type") == "admin_response":
                response_payload = response_message.get("payload")
                print("Response received.")
            elif response_message:
                print(f"Error: Received unexpected message type '{response_message.get('type')}' from server.")
                print(f"Full response: {response_message}")
            else:
                print("Error: No response or invalid response received from server admin interface.")
            
        except ConnectionResetError:
            print("Error: Connection to server admin interface was reset. Is the server running and key correct?")
        except Exception as e:
            print(f"An error occurred while communicating with the server admin interface: {e}")
        finally:
            self.client.disconnect()
            print("Disconnected from server admin interface.")
        
        return response_payload

    def get_detailed_queue(self):
        payload = self._send_admin_command("get_detailed_queue")
        if payload and payload.get('status') == 'success':
            queue = payload.get('queue', [])
            print("\n--- Detailed Job Queue ---")
            if queue:
                for job in queue:
                    print(f"  Job ID: {job.get('job_id')}")
                    print(f"    Status: {job.get('status')}")
                    print(f"    Primary File: {job.get('primary_input_file_name')}")
                    print(f"    Num Input Files: {job.get('num_input_files')}")
                    print(f"    Submitted (UTC): {job.get('submitted_at_utc')}")
                    print(f"    Input Dir: {job.get('job_input_dir_on_server')}")
                    print(f"    Client Options: {json.dumps(job.get('client_recon_options', {}), indent=6)}")
                    print("-" * 20)
            else:
                print("  Queue is empty.")
            print(f"Total jobs in queue: {payload.get('count', 0)}")
            print("------------------------\n")
        elif payload:
            print(f"\nError from server: {payload.get('message', 'Unknown error')}\n")
        else:
            print("\nFailed to get detailed queue from server.\n")

    def get_logs(self, lines: int, job_id_filter: str | None):
        params = {"lines": lines}
        if job_id_filter:
            params["jobid"] = job_id_filter
        
        payload = self._send_admin_command("get_logs", params)
        if payload and payload.get('status') == 'success':
            logs = payload.get('logs', "")
            print(f"\n--- Server Logs (Last {lines} lines{f' for Job ID {job_id_filter}' if job_id_filter else ''}) ---")
            print(logs.strip())
            print("-----------------------------------\n")
        elif payload:
            print(f"\nError from server: {payload.get('message', 'Unknown error')}\n")
        else:
            print("\nFailed to get logs from server.\n")

    def get_worker_status(self):
        payload = self._send_admin_command("get_worker_status")
        if payload and payload.get('status') == 'success':
            workers = payload.get('workers', [])
            print("\n--- Worker Status ---")
            if workers:
                for worker in workers:
                    print(f"  Worker: {worker.get('worker_name')} (ID: {worker.get('thread_id')})")
                    print(f"    Alive: {'Yes' if worker.get('alive') else 'No'}")
                    print(f"    Status: {worker.get('status')}")
                    print(f"    Current Job ID: {worker.get('current_job_id', 'N/A')}")
                    print(f"    Started (UTC): {worker.get('started_at_utc')}")
                    print("-" * 15)
            else:
                print("  No worker information available or no workers running.")
            print("---------------------\n")
        elif payload:
            print(f"\nError from server: {payload.get('message', 'Unknown error')}\n")
        else:
            print("\nFailed to get worker status from server.\n")

    def cancel_job(self, job_id: str):
        print(f"Attempting to cancel job: {job_id} (Note: This feature may be a placeholder on the server).")
        payload = self._send_admin_command("cancel_job", {"job_id": job_id})
        if payload:
            print(f"\nServer Response to Cancel Job {job_id}:")
            print(f"  Status: {payload.get('status')}")
            print(f"  Message: {payload.get('message')}\n")
        else:
            print(f"\nFailed to send cancel command for job {job_id} to server.\n")

    def set_max_jobs(self, count: int):
        print(f"Attempting to set max concurrent jobs to: {count} (Note: This feature may be a placeholder on the server).")
        payload = self._send_admin_command("set_max_jobs", {"count": count})
        if payload:
            print(f"\nServer Response to Set Max Jobs to {count}:")
            print(f"  Status: {payload.get('status')}")
            print(f"  Message: {payload.get('message')}\n")
        else:
            print(f"\nFailed to send set_max_jobs command to server.\n")


def main():
    parser = argparse.ArgumentParser(
        description="Command-Line Interface for the Recon Server's Admin Port.",
        formatter_class=argparse.RawTextHelpFormatter
    )
    parser.add_argument(
        "--opts", 
        default="recon.opts", 
        help="Path to the recon.opts configuration file (default: recon.opts)"
    )
    
    subparsers = parser.add_subparsers(
        dest="command", 
        required=True,
        help="Available admin commands"
    )
    
    # 'queue' command
    queue_parser = subparsers.add_parser("queue", help="Get the detailed job queue from the server.")
    
    # 'logs' command
    logs_parser = subparsers.add_parser("logs", help="View server logs.")
    logs_parser.add_argument(
        "--lines", 
        type=int, 
        default=100, 
        help="Number of recent log lines to retrieve (default: 100)."
    )
    logs_parser.add_argument(
        "--jobid", 
        type=str, 
        help="Filter logs for a specific Job ID."
    )
    
    # 'workers' command
    workers_parser = subparsers.add_parser("workers", help="View the status of server worker threads.")

    # 'cancel' command (Advanced)
    cancel_parser = subparsers.add_parser("cancel", help="Attempt to cancel a job (feature might be placeholder).")
    cancel_parser.add_argument("job_id", help="The ID of the job to cancel.")

    # 'setmaxjobs' command (Advanced)
    setmaxjobs_parser = subparsers.add_parser("setmaxjobs", help="Attempt to set max concurrent jobs (feature might be placeholder).")
    setmaxjobs_parser.add_argument("count", type=int, help="The new maximum number of concurrent jobs.")


    args = parser.parse_args()

    if not os.path.exists(args.opts):
        print(f"ERROR: Recon options file '{args.opts}' not found.")
        try:
            print(f"Attempting to create a default '{args.opts}' to guide configuration...")
            readoptions(args.opts) # This should create 'recon.opts' with defaults
            print(f"\nA default '{args.opts}' file has been created.")
            print("Please review and configure it, especially:")
            print("  - SERVER_HOSTNAME (if not localhost)")
            print("  - SERVER_ADMIN_PORT (if different from default 60003)")
            print("  - SERVER_ADMIN_SHARED_KEY (MUST be set to a secure, unique key)")
        except Exception as e:
            print(f"Could not create a default '{args.opts}': {e}")
        sys.exit(1)

    cli = None
    try:
        cli = ServerAdminCLI(args.opts)
    except SystemExit: 
        sys.exit(1) 
    except Exception as e: 
        print(f"Failed to initialize Server Admin CLI: {e}")
        sys.exit(1)

    if args.command == "queue":
        cli.get_detailed_queue()
    elif args.command == "logs":
        cli.get_logs(args.lines, args.jobid)
    elif args.command == "workers":
        cli.get_worker_status()
    elif args.command == "cancel":
        cli.cancel_job(args.job_id)
    elif args.command == "setmaxjobs":
        cli.set_max_jobs(args.count)
    else:
        print(f"Unknown command: {args.command}")
        parser.print_help()
        sys.exit(1)

if __name__ == "__main__":
    main()
