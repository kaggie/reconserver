# Secure Recon Server System

## Overview

This system provides a secure client-server architecture for requesting remote data processing, specifically tailored for medical image reconstruction tasks. It features encrypted file transfer for all data and commands, and robust job management capabilities including queuing and status reporting.

**Core Technologies:**
*   Python
*   Shared Key Encryption (AES via Fernet library)
*   Socket Communication (TCP/IP)

## Core Components

*   **`server_app.py`**: The main server application. It listens for client connections, handles incoming commands (job submission, status requests), manages a job queue, and dispatches processing tasks to worker threads. It's responsible for receiving input files, triggering external reconstruction scripts, and sending back results.
*   **`client_app.py`**: The main client application. It can be used to submit reconstruction jobs (including multiple input files and processing options), query the server's status, and view the current job queue. It handles the secure transfer of files to the server and receives processed results.
*   **`secure_transfer.py`**: This module contains the `SecureFileTransferServer` and `SecureFileTransferClient` classes, which implement the encrypted communication protocol using a shared Fernet key. All data and control messages are encrypted.
*   **`reconlibs.py`**: A library of shared utility functions, primarily for reading and writing configuration files (like `recon.opts` and `relay.opts` using the `ITEM = VALUE` format) and cryptographic helper functions.
*   **`relay_server.py`** (Experimental): A basic relay server component, intended to route client requests to backend reconstruction servers. It uses a `relay.opts` configuration file with a similar `ITEM = VALUE` format. (Further details will be provided when this component is more mature).

## Setup and Configuration (`recon.opts`)

The behavior of both the server and client applications is configured through a shared `recon.opts` file. This file must be present in the same directory as the script being run (or its path specified via CLI if that option is added). If not found, a default `recon.opts` will be created by the application using the new `ITEM = VALUE` format.

The `recon.opts` file uses a simple `ITEM = VALUE` format:
*   Each line should contain a single key-value pair, such as `SERVER_HOSTNAME = localhost`.
*   Keys are case-insensitive during parsing (e.g., `server_hostname` is treated the same as `SERVER_HOSTNAME`) but are typically written in uppercase in documentation and default files. The system stores them internally in uppercase.
*   Values are parsed with type inference:
    *   `true` or `false` (case-insensitive) become boolean `True` or `False`.
    *   Numeric values that are valid integers (e.g., `60000`, `-10`) are converted to integers.
    *   Strings enclosed in double (`"`) or single (`'`) quotes will have the quotes removed (e.g., `"*.7"` becomes `*.7`).
    *   Other values are treated as strings.
*   Lines starting with a `#` symbol are considered comments and are ignored.
*   Blank lines are also ignored.

**It is CRITICAL to generate a secure `SHARED_KEY` and configure it in `recon.opts` on both the server and any client machines.**

To generate a new shared key, run:
`python -c "from reconlibs import generate_key; print(generate_key())"`

Copy the output string and paste it as the value for the `SHARED_KEY` item.

**Example `recon.opts` File:**

```
# recon.opts - Configuration for Recon Server and Client

# --- Server Configuration ---
SERVER_HOSTNAME = localhost
SERVER_PORT = 60000

# --- Security ---
# SHARED_KEY: A securely generated Fernet key for encrypting transfers.
# IMPORTANT: Generate using the command provided in the README.
# This key MUST be identical on both the client and server.
SHARED_KEY = SET_YOUR_SHARED_KEY_HERE

# TRUSTED_IPS: Comma-separated list of client IP addresses allowed to connect to the server.
# Example: TRUSTED_IPS = 192.168.1.101,192.168.1.102,::1
# If commented out or empty, the server may allow all IPs (depending on server_app logic).
# For no IP restriction, leave the value blank or comment out the line:
# TRUSTED_IPS =
TRUSTED_IPS = 127.0.0.1,::1

# --- Paths ---
# Server's base directory for downloaded PFILEs and job-specific input subdirectories
RECON_SERVER_BASE_PFILE_DIR = /tmp/recon_server_pfiles

# Full path or name of the reconstruction script on the server
# Examples: /opt/scripts/matlab_recon.sh, python_recon.py, default_recon_script.sh
RECON_SCRIPT_PATH = default_recon_script.sh

# Server's directory where reconstructed DICOMs are stored (and from where they are sent to client)
RECON_SERVER_DICOM_OUTPUT_DIR = /tmp/recon_server_dicoms

# --- Logging ---
LOG_FILEPATH = /tmp/recon_project.log

# --- Server Settings ---
# MAX_CONCURRENT_JOBS: Max number of recon jobs server processes simultaneously.
MAX_CONCURRENT_JOBS = 1

# --- Client Application Default Options (for client_app.py) ---
CLIENT_DEFAULT_PFILE_NAME = P00000.7
CLIENT_DEFAULT_PFILE_PATH = /tmp/default_pfile_on_client/P00000.7
CLIENT_DOWNLOAD_DIR = client_downloads

# --- Legacy Options (Generally not used by current core server logic but kept for reference/defaults) ---
# These are often commented out in the default generated file.
# SCANNER_USERNAME = sdc
# SCANNER_PASSWORD = adw2.0
# SSH_PORT = 22
# SOURCE_DATA_PATH = /usr/g/mrraw/
# SCANNER_DICOM_SOURCE_DIR = /tmp/scanner_dicoms/

# --- Client Daemon Specific Options (for a separate client_daemon.py, if used) ---
# These are often commented out in the default generated file or have empty/default values.
# CLIENT_WATCH_DIRECTORY = /path/to/watch # Example of a path
CLIENT_WATCH_DIRECTORY = 
CLIENT_WATCH_PATTERN = "*.7"
# CLIENT_DAEMON_POLL_INTERVAL = 10
# CLIENT_DAEMON_STABILITY_DELAY = 5
# CLIENT_DAEMON_GROUPING_TIMEOUT = 5
# CLIENT_DAEMON_RECON_OPTIONS_JSON = {}
```

**Note on Legacy Options:**
The `SCANNER_USERNAME`, `SCANNER_PASSWORD`, `SSH_PORT`, `SOURCE_DATA_PATH`, and `SCANNER_DICOM_SOURCE_DIR` options are primarily legacy. The current system relies on the client sending input files directly. These options are retained in the default configuration file (often commented out) for potential backward compatibility or specific site setups but are not actively used by the core `server_app.py` logic for file acquisition in the primary workflow.

## Workflow & Features

The system operates on a client-initiated command model.

### Job Submission (Client-Initiated)

1.  The client (`client_app.py`) initiates a connection to the server.
2.  The client sends a `submit_recon_job` command. This command's payload includes:
    *   `files`: A list of dictionaries, where each dictionary describes an input file. Each file dictionary contains:
        *   `name`: The basename of the file.
        *   `original_path_on_client`: The full path to the file on the client's machine.
    *   `client_recon_options_json`: A JSON string representing a dictionary of reconstruction parameters (e.g., `{"slice_thickness": "2mm", "algorithm": "filtered_backprojection"}`).
    *   The client CLI supports specifying multiple files directly (`--files /path/to/P00000.7 /path/to/calibration.dat`) or a directory with a pattern (`--directory /scans/today --pattern "*.dat"`).

### Server Processing

1.  The server receives the `submit_recon_job` command.
2.  A unique `job_id` (UUID) is generated for the job.
3.  A job-specific input directory is created on the server under the path specified by `RECON_SERVER_BASE_PFILE_DIR` in `recon.opts` (e.g., `/tmp/recon_server_pfiles/job_<uuid>_input/`).
4.  The server iterates through the `files` list received from the client:
    *   For each file, it sends a `request_file` command to the client, specifying the `original_path_on_client`.
    *   The client responds by sending the requested file.
    *   The server receives the file and saves it into the job-specific input directory.
5.  Once all files are received, the job (containing the `job_id`, path to the `job_input_dir_on_server`, number of input files, primary input file name, submission timestamp, initial status "queued", and `client_recon_options`) is added to an internal queue.
6.  The server sends a `job_queued` message back to the client, including the `job_id` and the number of files received.
7.  A worker thread on the server picks up the job from the queue (status then changes to "processing" conceptually).
8.  The worker thread executes the `RECON_SCRIPT_PATH` (defined in `recon.opts`).
    *   The primary argument passed to this script is the path to the `job_input_dir_on_server`.
    *   Reconstruction options from `client_recon_options` are passed as additional command-line arguments. For Python/shell scripts, these are typically passed as `--key value`. For Matlab scripts, they are passed as sequential string arguments `'key', 'value', 'key2', 'value2...'`. The external script must be designed to parse these arguments.
9.  The reconstruction script is expected to write its output (e.g., DICOM files) to a directory. The server currently looks for these outputs in the general `RECON_SERVER_DICOM_OUTPUT_DIR`. (Future enhancements may involve job-specific output directories managed by the server or script).
10. If DICOM files (or other results) are found, the server sends a `dicom_transfer_start` command to the client (including the number of files). The client must acknowledge with a status of "ready".
11. The server then sends each result file to the client. These are saved in the client's `CLIENT_DOWNLOAD_DIR`.
12. Upon successful completion (including file transfer), the server sends a `recon_complete` message. If any part of the processing or script execution fails, a `job_failed` message is sent.
13. The job-specific input directory on the server is automatically cleaned up (deleted) after the job is processed (whether success or failure).

### Server Status & Queue Viewing (Client CLI)

Clients can query the server without submitting a job:

*   **`python client_app.py --server-status`**:
    *   The client connects and sends a `get_server_status` command.
    *   The server responds with `server_status_response` containing:
        *   Server uptime.
        *   Configured maximum number of worker threads (`MAX_CONCURRENT_JOBS`).
        *   Current number of active worker threads.
        *   Number of jobs currently in the queue.
    *   The client displays this information.

*   **`python client_app.py --view-queue`**:
    *   The client connects and sends a `get_queue_details` command.
    *   The server responds with `queue_details_response` containing a list of jobs currently in its queue. For each job, details include:
        *   Job ID.
        *   Status (e.g., "queued").
        *   Primary input file name.
        *   Number of input files.
        *   Submission time (UTC).
        *   Basename of the job's input directory on the server.
    *   The client displays this list.

## Running the Applications

### Server
```bash
python server_app.py
```
The server will use `recon.opts` found in its current working directory. Ensure `recon.opts` is configured correctly, especially `SHARED_KEY`, paths (like `RECON_SERVER_BASE_PFILE_DIR`, `RECON_SCRIPT_PATH`), and `MAX_CONCURRENT_JOBS`.

### Client (Submitting Reconstruction Jobs)
To submit one or more specific files:
```bash
python client_app.py --files /path/to/PFILE.7 /path/to/another_input.dat --recon-options '{"option1": "value1", "num_slices": 128}'
```

To submit all files matching a pattern in a directory:
```bash
python client_app.py --directory /path/to/scan_data/ --pattern "*.dcm" --recon-options '{"custom_script_param": true}'
```

If no files or directory are specified, the client will attempt to use `CLIENT_DEFAULT_PFILE_PATH` from `recon.opts` (if the file exists).

### Client (Querying Server)
To check server status:
```bash
python client_app.py --server-status
```

To view the job queue:
```bash
python client_app.py --view-queue
```

## Triggering External Code

The primary mechanism for external code execution is the `RECON_SCRIPT_PATH` defined in `recon.opts`.
*   This script is executed by the server's worker threads.
*   The main argument passed to this script is now the **path to the job-specific input directory** which contains all files submitted by the client for that job.
*   Additional parameters from the client's `--recon-options` are passed as command-line arguments to the script.
    *   For Python/shell scripts: `--key value`
    *   For Matlab scripts: `'key', 'value'` (passed as sequential string arguments to the Matlab function).
*   The script is responsible for performing the reconstruction and placing output files (e.g., DICOMs) in a location accessible by the server (currently the general `RECON_SERVER_DICOM_OUTPUT_DIR`, though future improvements might make this job-specific).

## Security

*   **Encryption:** All communication between the client and server, including file data and control messages, is encrypted using AES via the Fernet library. This relies on a pre-shared `SHARED_KEY`.
*   **Shared Key:** The `SHARED_KEY` in `recon.opts` is critical. It must be kept secret and be identical on the server and all authorized clients.
*   **Trusted IPs:** The server can be configured with a list of `TRUSTED_IPS` in `recon.opts`. If this list is populated, the server will only accept connections from these IP addresses, providing an additional layer of access control. If empty or commented out, the server may accept connections from any IP (depending on firewall configurations).

---
This README reflects the system's state after recent refactoring, including changes to the configuration file format (now `ITEM = VALUE`) and the introduction of an experimental relay server.
```
