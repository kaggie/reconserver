# Secure Reconnaissance Server System

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
*   **`reconlibs.py`**: A library of shared utility functions, primarily for reading and writing the `recon.opts` configuration file and cryptographic helper functions.

## Setup and Configuration (`recon.opts`)

The behavior of both the server and client applications is configured through a shared `recon.opts` file. This file must be present in the same directory as the script being run (or its path specified via CLI if that option is added). If not found, a default `recon.opts` will be created.

**It is CRITICAL to generate a secure `SHARED_KEY` and configure it in `recon.opts` on both the server and any client machines.**

To generate a new shared key, run:
`python -c "from reconlibs import generate_key; print(generate_key())"`

Copy the output string and paste it as the value for `SHARED_KEY`.

**Example `recon.opts` Structure:**

```
# Recon server IP address or hostname (e.g., localhost, 192.168.1.100)
localhost
# Port for recon server communication (e.g., 60000)
60000
# Username for scanner authentication (legacy, may not be used by current server)
sdc
# Password for scanner authentication (legacy, may not be used by current server)
adw2.0
# SSH port for secure shell access (legacy, currently unused by server_app)
22
# Path to source data (legacy, MRRAW directory, less relevant if PFILE sent by client)
/usr/g/mrraw/
# Server's base directory for downloaded PFILEs and job-specific input subdirectories
/tmp/recon_server_pfiles
# Full path or name of the reconstruction script on the server (e.g., /opt/scripts/matlab_recon.sh or python_recon.py)
default_recon_script.sh
# Server's directory where reconstructed DICOMs are stored (and from where they are sent to client)
/tmp/recon_server_dicoms
# Scanner's DICOM directory (legacy, less relevant if DICOMs are sent back to client)
/tmp/scanner_dicoms/
# Path to the log file for server and client applications (can be overridden by client/daemon specific opts)
/tmp/recon_project.log
# --- Secure Transfer Options ---
# SHARED_KEY: A securely generated Fernet key for encrypting transfers.
# IMPORTANT: Generate using: python -c "from reconlibs import generate_key; print(generate_key())"
# Copy the output key and paste it here, replacing the placeholder.
# This key MUST be identical on both the client and server.
SHARED_KEY = SET_YOUR_SHARED_KEY_HERE
# --- Server Specific Options ---
# MAX_CONCURRENT_JOBS: Max number of recon jobs server processes simultaneously (e.g., 1 for sequential).
MAX_CONCURRENT_JOBS = 1
# TRUSTEDIPS: Comma-separated list of client IP addresses allowed to connect to the server.
# Example: #TRUSTEDIPS: 192.168.1.101,192.168.1.102
# If commented out or empty, the server may allow all IPs (check server_app logic).
#TRUSTEDIPS: 127.0.0.1,::1
# --- Client Daemon Options (for client_daemon.py) ---
# CLIENT_WATCH_DIRECTORY = 
# CLIENT_WATCH_PATTERN = *.7
# CLIENT_DAEMON_POLL_INTERVAL = 10 # (Used by daemon if watchdog is not active/available)
# CLIENT_DAEMON_STABILITY_DELAY = 5
# CLIENT_DAEMON_GROUPING_TIMEOUT = 5
# CLIENT_DAEMON_RECON_OPTIONS_JSON = {}
# --- Standard Client Application Options (for client_app.py) ---\
CLIENT_DEFAULT_PFILE_NAME = P00000.7
CLIENT_DEFAULT_PFILE_PATH = /tmp/default_pfile_on_client/P00000.7
CLIENT_DOWNLOAD_DIR = client_downloads
```

**Note on Legacy Options:**
The `USERNAME`, `PASSWORD`, `SSHPORT` (for scanner authentication), `MRRAW_PATH` (source data path on scanner), and `SCANNER_DICOM_DIR` options are largely legacy from an older version of the system. The current client-server model primarily relies on the client sending the necessary input files directly. These options are retained for potential backward compatibility or specific site setups but are not actively used by the core `server_app.py` logic for file acquisition in the primary workflow.

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
3.  A job-specific input directory is created on the server under the path specified by `RECON_FILEPATH` in `recon.opts` (e.g., `/tmp/recon_server_pfiles/job_<uuid>_input/`).
4.  The server iterates through the `files` list received from the client:
    *   For each file, it sends a `request_file` command to the client, specifying the `original_path_on_client`.
    *   The client responds by sending the requested file.
    *   The server receives the file and saves it into the job-specific input directory.
5.  Once all files are received, the job (containing the `job_id`, path to the `job_input_dir_on_server`, number of input files, primary input file name, submission timestamp, initial status "queued", and `client_recon_options`) is added to an internal queue.
6.  The server sends a `job_queued` message back to the client, including the `job_id` and the number of files received.
7.  A worker thread on the server picks up the job from the queue (status then changes to "processing" conceptually).
8.  The worker thread executes the `RECON_SCRIPT` (defined in `recon.opts`).
    *   The primary argument passed to this script is the path to the `job_input_dir_on_server`.
    *   Reconstruction options from `client_recon_options` are passed as additional command-line arguments. For Python/shell scripts, these are typically passed as `--key value`. For Matlab scripts, they are passed as sequential string arguments `'key', 'value', 'key2', 'value2...'`. The external script must be designed to parse these arguments.
9.  The reconstruction script is expected to write its output (e.g., DICOM files) to a directory. The server currently looks for these outputs in the general `RECON_DICOM_DIR`. (Future enhancements may involve job-specific output directories managed by the server or script).
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
The server will use `recon.opts` found in its current working directory. Ensure `recon.opts` is configured correctly, especially `SHARED_KEY`, paths, and `MAX_CONCURRENT_JOBS`.

### Client (Submitting Reconstruction Jobs)
To submit one or more specific files:
```bash
python client_app.py --files /path/to/PFILE.7 /path/to/another_input.dat --recon-options '{"option1": "value1", "num_slices": 128}'
```

To submit all files matching a pattern in a directory:
```bash
python client_app.py --directory /path/to/scan_data/ --pattern "*.dcm" --recon-options '{"custom_script_param": true}'
```

If no files or directory are specified, the client will attempt to use `CLIENT_DEFAULT_PFILE_PATH` from `recon.opts`.

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

The primary mechanism for external code execution is the `RECON_SCRIPT` defined in `recon.opts`.
*   This script is executed by the server's worker threads.
*   The main argument passed to this script is now the **path to the job-specific input directory** which contains all files submitted by the client for that job.
*   Additional parameters from the client's `--recon-options` are passed as command-line arguments to the script.
    *   For Python/shell scripts: `--key value`
    *   For Matlab scripts: `'key', 'value'` (passed as sequential string arguments to the Matlab function).
*   The script is responsible for performing the reconstruction and placing output files (e.g., DICOMs) in a location accessible by the server (currently the general `RECON_DICOM_DIR`, though future improvements might make this job-specific).

## Security

*   **Encryption:** All communication between the client and server, including file data and control messages, is encrypted using AES via the Fernet library. This relies on a pre-shared `SHARED_KEY`.
*   **Shared Key:** The `SHARED_KEY` in `recon.opts` is critical. It must be kept secret and be identical on the server and all authorized clients.
*   **Trusted IPs:** The server can be configured with a list of `TRUSTEDIPS` in `recon.opts`. If this list is populated, the server will only accept connections from these IP addresses, providing an additional layer of access control. If empty or commented out, the server may accept connections from any IP (depending on firewall configurations).

---
This README reflects the system's state after Phase 2 development.
```
