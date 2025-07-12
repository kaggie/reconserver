import os
import sys
import time
import threading
import subprocess
import matplotlib.pyplot as plt

# Add the parent directory to the path to allow imports
sys.path.append(os.path.abspath(os.path.join(os.path.dirname(__file__), '..')))

from client_app import ReconClientApp
from server_app import ReconServerApp

def run_server(server):
    """Function to run the server in a thread."""
    print("Starting server...")
    try:
        server.run()
    except Exception as e:
        print(f"Server thread failed: {e}")

def main():
    """Main function to run the example."""
    # -- 1. Setup --
    opts_file = "example/recon.opts"
    dummy_file = "example/dummy_file.txt"
    plot_file = "example/transfer_time.png"
    ports = [60000, 60001, 60002]

    # -- 2. Server and Client Instantiation --
    server = None
    for port in ports:
        try:
            # Modify recon.opts to use the current port
            with open(opts_file, 'r') as f:
                lines = f.readlines()
            with open(opts_file, 'w') as f:
                for line in lines:
                    if line.startswith("SERVER_PORT"):
                        f.write(f"SERVER_PORT = {port}\n")
                    else:
                        f.write(line)

            server = ReconServerApp(options_file=opts_file)
            print(f"Attempting to start server on port {port}...")
            # The server's 'start' method binds the socket. If it fails, we'll know here.
            if server.sf_server.start():
                print(f"Server started successfully on port {port}.")
                break # Exit the loop if the server started successfully
            else:
                print(f"Failed to start server on port {port}. Trying next port.")
                server = None
        except Exception as e:
            print(f"Could not start server on port {port}: {e}. Trying next port.")
            server = None

    if not server:
        print("Failed to start server on any of the specified ports. Exiting.")
        sys.exit(1)

    server_thread = threading.Thread(target=run_server, args=(server,))
    server_thread.daemon = True
    server_thread.start()
    time.sleep(2)  # Give the server a moment to start listening

    # -- 3. Run Client and Measure Transfer Time --
    start_time = time.time()

    try:
        client = ReconClientApp(options_file=opts_file)
        if not client.connect():
            print("Client failed to connect.")
            # Stop the server before exiting
            server.stop_server()
            server_thread.join()
            sys.exit(1)

        job_id = client.submit_recon_job(files_to_process=[dummy_file])
        if job_id:
            print(f"Job submitted with ID: {job_id}")
            client.process_job_and_get_results(job_id)
        else:
            print("Failed to submit job.")

        client.disconnect()
    except Exception as e:
        print(f"An error occurred during the client operation: {e}")
    finally:
        end_time = time.time()
        # Ensure server is stopped
        server.stop_server()
        # Wait for the server thread to finish
        server_thread.join(timeout=5)
        if server_thread.is_alive():
            print("Server thread did not terminate cleanly.")

    transfer_time = end_time - start_time
    print(f"Total transfer time: {transfer_time:.4f} seconds")

    # -- 4. Generate and Save Plot --
    try:
        plt.figure()
        plt.bar(['Transfer Time'], [transfer_time])
        plt.ylabel('Time (seconds)')
        plt.title('Client-Server Transfer Time')
        plt.savefig(plot_file)
        print(f"Plot saved to {plot_file}")
    except Exception as e:
        print(f"Failed to generate or save plot: {e}")

if __name__ == "__main__":
    main()
