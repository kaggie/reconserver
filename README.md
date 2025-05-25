# Secure Reconnaissance Server System

## Overview

This system provides a secure client-server architecture for requesting remote data processing, specifically tailored for medical image reconstruction tasks. It features encrypted file transfer for all data and commands, robust job management, and administrative interfaces for monitoring and control. Recent enhancements include structured JSON logging, basic server resource management, job-specific output directories, and CLI tools for server administration.

**Core Technologies:**
*   Python
*   Shared Key Encryption (AES via Fernet library)
*   Socket Communication (TCP/IP)
*   JSON-structured logging

## Core Components

*   **`server_app.py`**: The main server application. It listens for client connections, handles incoming commands (job submission, status requests), manages a job queue, and dispatches processing tasks to worker threads. It's responsible for receiving input files, triggering external reconstruction scripts, and sending back results. Includes an admin interface for monitoring and control.
*   **`client_app.py`**: The main client application. It can be used to submit reconstruction jobs (including multiple input files and processing options), query the server's status, and view the current job queue. It handles the secure transfer of files to the server and receives processed results.
*   **`secure_transfer.py`**: This module contains the `SecureFileTransferServer` and `SecureFileTransferClient` classes, which implement the encrypted communication protocol using a shared Fernet key. All data and control messages are encrypted.
*   **`reconlibs.py`**: A library of shared utility functions, primarily for reading and writing configuration files (like `recon.opts` and `relay.opts` using the `ITEM = VALUE` format) and cryptographic helper functions.
*   **`relay_server.py`** (Experimental): A basic relay server component, intended to route client requests to backend reconstruction servers. It uses a `relay.opts` configuration file with a similar `ITEM = VALUE` format and also features an admin interface.
*   **`server_admin_cli.py`**: A command-line tool for administering and monitoring `server_app.py`.
*   **`relay_server_cli.py`**: A command-line tool for administering and monitoring `relay_server.py`.
*   **`example_usage.ipynb`**: A Jupyter Notebook demonstrating programmatic interaction with `server_app.py`.

## Dependencies

The system requires the following Python libraries:
*   `cryptography`: For Fernet encryption.
*   `psutil`: For server resource monitoring (CPU/memory).
*   `python-json-logger`: For structured JSON logging.

Install them using pip:
```bash
pip install cryptography psutil python-json-logger
```

## Setup and Configuration

Configuration for the server, client, and relay is managed through `.opts` files, which use an `ITEM = VALUE` format.
*   Each line should contain a single key-value pair (e.g., `SERVER_HOSTNAME = localhost`).
*   Keys are case-insensitive during parsing but are typically written in uppercase.
*   Values are type-inferred: booleans (`true`/`false`), integers, and strings (quotes are stripped).
*   Lines starting with `#` are comments. Blank lines are ignored.
*   If a config file is not found, a default one will be created by the respective application.

**CRITICAL: Shared Key Generation**
Secure, unique shared keys are essential for encrypted communication. Use the following command to generate a key:
```bash
python -c "from reconlibs import generate_key; print(generate_key())"
```
**Separate keys MUST be generated and configured for:**
1.  Client-Server communication (`SHARED_KEY` in `recon.opts`).
2.  Server Admin interface (`SERVER_ADMIN_SHARED_KEY` in `recon.opts`).
3.  Relay Client-Facing interface (`SHARED_KEY_RELAY_TO_CLIENTS` in `relay.opts`).
4.  Relay Admin interface (`RELAY_ADMIN_SHARED_KEY` in `relay.opts`).

### Main Server Configuration (`recon.opts`)

**Example `recon.opts` File:**
```
# recon.opts - Configuration for Recon Server (server_app.py) and Client (client_app.py)

# --- Server Main Connection ---
SERVER_HOSTNAME = localhost
SERVER_PORT = 60000
SHARED_KEY = SET_YOUR_SHARED_KEY_HERE # For client-server communication

# --- Security ---
TRUSTED_IPS = 127.0.0.1,::1 # Comma-separated, or blank for no IP restriction

# --- Paths ---
RECON_SERVER_BASE_PFILE_DIR = /tmp/recon_server_pfiles # Base for job-specific input subdirs
RECON_SCRIPT_PATH = default_recon_script.sh           # Path to the reconstruction script
RECON_JOB_OUTPUT_BASE_DIR = /tmp/recon_server_job_outputs # Base for job-specific output subdirs
# RECON_SERVER_DICOM_OUTPUT_DIR = /tmp/recon_server_dicoms # Legacy global output, now job-specific

# --- Logging ---
LOG_FILEPATH = /tmp/recon_project.log
LOG_LEVEL = INFO # DEBUG, INFO, WARNING, ERROR (for JSON structured logging)

# --- Server Settings ---
MAX_CONCURRENT_JOBS = 1

# --- Resource Management (Server) ---
MAX_CPU_LOAD_PERCENT = 75          # e.g., 75 for 75%. Server pauses if CPU load exceeds this.
MIN_AVAILABLE_MEMORY_MB = 500      # e.g., 500 for 500MB. Server pauses if available RAM drops below this.
RESOURCE_CHECK_INTERVAL_SECONDS = 10 # How often to check resources when constrained.

# --- Server Admin Interface (for server_admin_cli.py) ---
SERVER_ADMIN_PORT = 60003
SERVER_ADMIN_SHARED_KEY = SET_YOUR_SERVER_ADMIN_KEY_HERE # MUST be different from main SHARED_KEY

# --- Client Application Default Options (for client_app.py) ---
CLIENT_DEFAULT_PFILE_NAME = P00000.7
CLIENT_DEFAULT_PFILE_PATH = /tmp/default_pfile_on_client/P00000.7
CLIENT_DOWNLOAD_DIR = client_downloads

# --- Legacy Options (Commented out - generally not used by current core server logic) ---
# SCANNER_USERNAME = sdc
# SCANNER_PASSWORD = adw2.0
# SSH_PORT = 22
# SOURCE_DATA_PATH = /usr/g/mrraw/
# SCANNER_DICOM_SOURCE_DIR = /tmp/scanner_dicoms/

# --- Client Daemon Specific Options (for a separate client_daemon.py, if used) ---
# CLIENT_WATCH_DIRECTORY = 
# CLIENT_WATCH_PATTERN = "*.7"
# CLIENT_DAEMON_POLL_INTERVAL = 10
# CLIENT_DAEMON_STABILITY_DELAY = 5
# CLIENT_DAEMON_GROUPING_TIMEOUT = 5
# CLIENT_DAEMON_RECON_OPTIONS_JSON = {}
```

### Relay Server Configuration (`relay.opts`)

**Example `relay.opts` File:**
```
# relay.opts - Configuration for Relay Server (relay_server.py)

RELAY_HOSTNAME = localhost
RELAY_PORT = 60001 # Port for clients to connect to the relay

# --- Logging ---
LOG_FILEPATH = /tmp/relay_server.log
LOG_LEVEL = INFO # DEBUG, INFO, WARNING, ERROR

# --- Security (Client-Facing) ---
SHARED_KEY_RELAY_TO_CLIENTS = SET_YOUR_RELAY_TO_CLIENTS_KEY_HERE
# TRUSTED_CLIENT_IPS = 127.0.0.1,192.168.1.0/24 # Optional: IPs allowed to connect to relay

# --- Backend Reconstruction Servers ---
# Comma-separated list of host:port pairs
BACKEND_SERVERS = localhost:60000 

# --- Relay Admin Interface (for relay_server_cli.py) ---
RELAY_ADMIN_PORT = 60002
RELAY_ADMIN_SHARED_KEY = SET_YOUR_RELAY_ADMIN_KEY_HERE # MUST be different from SHARED_KEY_RELAY_TO_CLIENTS
```

## Workflow & Features

### Job Submission & Processing (Server)
The server (`server_app.py`) processes reconstruction jobs as follows:
1.  Client submits a job with input files and options.
2.  Server creates a job-specific input directory under `RECON_SERVER_BASE_PFILE_DIR`.
3.  Server creates a job-specific output directory under `RECON_JOB_OUTPUT_BASE_DIR`.
4.  The external script specified by `RECON_SCRIPT_PATH` is executed.
    *   It receives the path to the job input directory as a primary argument.
    *   It also receives the path to the job-specific output directory via an `--output-dir` argument. The script **must** write its results here.
5.  Results from the job-specific output directory are sent back to the client.
6.  Both job-specific input and output directories are cleaned up after the job is completed or fails.

### Server Resource Management
`server_app.py` includes basic resource management:
*   If average CPU load (via `MAX_CPU_LOAD_PERCENT`) or available memory (via `MIN_AVAILABLE_MEMORY_MB`) thresholds are breached, the server's worker threads will pause fetching new jobs from the queue.
*   They will wait for `RESOURCE_CHECK_INTERVAL_SECONDS` before re-checking resources. This prevents the server from being overwhelmed.

## Running the Applications

### Server (`server_app.py`)
```bash
python server_app.py
```
Ensure `recon.opts` is configured, especially shared keys, paths, and resource limits.

### Client (`client_app.py`)
(Usage examples remain the same as previously documented for submitting jobs, viewing status, and queue.)

## Administrative CLI Tools

These tools use the admin interfaces on `server_app.py` and `relay_server.py` for monitoring and management. Ensure the respective `.opts` files are configured with the correct admin port and shared key.

### `server_admin_cli.py` (for `server_app.py`)
Manages and monitors the main reconstruction server.
*   **Commands:**
    *   `queue`: View detailed job queue.
    *   `logs [--lines N] [--jobid JOB_ID]`: View server logs (optionally filtered).
    *   `workers`: View status of worker threads.
    *   `cancel <job_id>`: (Placeholder) Attempt to cancel a job.
    *   `setmaxjobs <count>`: (Placeholder) Attempt to set max concurrent jobs.
*   **Usage Examples:**
    ```bash
    python server_admin_cli.py queue --opts recon.opts
    python server_admin_cli.py logs --lines 50 --jobid <some_job_id> --opts recon.opts
    python server_admin_cli.py workers --opts recon.opts
    ```

### `relay_server_cli.py` (for `relay_server.py`)
Manages and monitors the relay server.
*   **Commands:**
    *   `status`: Get relay server status (uptime, client counts).
    *   `backends`: View health of backend reconstruction servers.
    *   `clients`: List clients connected to the relay.
*   **Usage Examples:**
    ```bash
    python relay_server_cli.py status --opts relay.opts
    python relay_server_cli.py backends --opts relay.opts
    ```

## Example Jupyter Notebook (`example_usage.ipynb`)

An example Jupyter Notebook, `example_usage.ipynb`, is provided in the project root to demonstrate programmatic interaction with `server_app.py`.

*   **Purpose**: Useful for testing, scripting batch submissions, or integrating server interactions into other Python workflows.
*   **Demonstrates**:
    *   Initializing `ReconClientApp`.
    *   Connecting to and disconnecting from the server.
    *   Submitting jobs with dummy files and custom options.
    *   Querying server status and job queue details.
*   **How to Run**:
    1.  Ensure `server_app.py` is running and `recon.opts` is correctly configured (especially `SERVER_HOSTNAME`, `SERVER_PORT`, and `SHARED_KEY`).
    2.  Install Jupyter Notebook/Lab: `pip install notebook` or `pip install jupyterlab`.
    3.  Navigate to the project root directory in your terminal.
    4.  Run `jupyter notebook` or `jupyter lab`.
    5.  Open `example_usage.ipynb` in the Jupyter interface and run the cells sequentially.
    6.  The notebook creates dummy files locally for submission.

## Security

*   **Encryption:** All communication relies on pre-shared Fernet keys.
*   **Shared Keys:** Keep all shared keys (`SHARED_KEY`, `SERVER_ADMIN_SHARED_KEY`, `SHARED_KEY_RELAY_TO_CLIENTS`, `RELAY_ADMIN_SHARED_KEY`) secret and ensure they are unique for their respective purposes.
*   **Trusted IPs:** Use `TRUSTED_IPS` (in `recon.opts`) and `TRUSTED_CLIENT_IPS` (in `relay.opts`) for an additional layer of IP-based access control.
*   **Logging**: Server logs are now in JSON format, which can be integrated with centralized logging systems for security monitoring.

---
This README reflects the system's state after significant enhancements including admin CLIs, JSON logging, and resource management.
```
