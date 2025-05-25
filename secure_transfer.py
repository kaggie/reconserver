# -*- coding: utf-8 -*-
"""
secure_transfer.py: Provides classes for secure file and command transfer.

This module defines SecureFileTransferClient and SecureFileTransferServer
classes that use encryption for all communications.
"""

import socket
import os
import json
import base64
import struct # For packing/unpacking message length

try:
    from reconlibs import encrypt_data, decrypt_data
except ImportError:
    # This is a fallback for environments where reconlibs might not be in PYTHONPATH
    # In a real scenario, ensure reconlibs.py is accessible.
    print("Warning: Could not import reconlibs. Ensure it's in your PYTHONPATH.")
    def encrypt_data(data: bytes, key_string: str) -> bytes:
        """Placeholder encrypt_data if reconlibs is not found."""
        print("Warning: Using placeholder encrypt_data!")
        # This is NOT a real encryption, just a pass-through for placeholder.
        # Replace with actual Fernet usage if reconlibs is truly unavailable.
        return data

    def decrypt_data(encrypted_data: bytes, key_string: str) -> bytes | None:
        """Placeholder decrypt_data if reconlibs is not found."""
        print("Warning: Using placeholder decrypt_data!")
        # This is NOT a real decryption.
        return encrypted_data

# Define a fixed size for the message length header (e.g., 4 bytes for an integer)
MSG_LENGTH_HEADER_SIZE = 4


class SecureFileTransferClient:
    """
    Client for secure file transfers and command execution.

    Handles connection, sending/receiving encrypted messages,
    file transfers, and command exchange with a SecureFileTransferServer.
    """
    def __init__(self, host: str, port: int, shared_key: str, buffer_size: int = 4096):
        """
        Initializes the SecureFileTransferClient.

        Args:
            host: The server's hostname or IP address.
            port: The server's port number.
            shared_key: The base64 encoded Fernet key for encryption.
            buffer_size: The size of the buffer for receiving data.
        """
        self.host = host
        self.port = port
        self.shared_key = shared_key
        self.buffer_size = buffer_size
        self.socket: socket.socket | None = None
        self._receiving_file_info = {} # To store state during file reception from server

    def connect(self) -> bool:
        """
        Connects to the server.

        Returns:
            True if connection was successful, False otherwise.
        """
        try:
            self.socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            self.socket.connect((self.host, self.port))
            print(f"Successfully connected to server at {self.host}:{self.port}")
            return True
        except socket.error as e:
            print(f"Error connecting to server {self.host}:{self.port}: {e}")
            self.socket = None
            return False

    def disconnect(self):
        """Closes the connection to the server."""
        if self.socket:
            try:
                self.socket.close()
                print("Disconnected from server.")
            except socket.error as e:
                print(f"Error closing socket: {e}")
            finally:
                self.socket = None

    def _send_message(self, message_type: str, payload: dict) -> bool:
        """
        Constructs, encrypts, and sends a message to the server.

        The message is a JSON string: {"type": message_type, "payload": payload}.
        The JSON string is utf-8 encoded, then encrypted.
        The length of the encrypted message is sent as a fixed-size header first.

        Args:
            message_type: The type of the message (e.g., "file_transfer_start", "command").
            payload: A dictionary containing the message payload.

        Returns:
            True if the message was sent successfully, False otherwise.
        """
        if not self.socket:
            print("Error: Not connected to any server.")
            return False
        try:
            message_data = {"type": message_type, "payload": payload}
            json_string = json.dumps(message_data)
            encrypted_message = encrypt_data(json_string.encode('utf-8'), self.shared_key)
            
            # Pack the length of the encrypted message into a fixed-size header
            message_length_header = struct.pack('>I', len(encrypted_message)) # >I for big-endian unsigned int

            self.socket.sendall(message_length_header)
            self.socket.sendall(encrypted_message)
            # print(f"Sent message: Type={message_type}, Payload Size (Encrypted)={len(encrypted_message)}")
            return True
        except socket.error as e:
            print(f"Socket error sending message: {e}")
            return False
        except Exception as e:
            print(f"Error sending message: {e}")
            return False

    def _receive_message(self) -> dict | None:
        """
        Receives, decrypts, and parses a message from the server.

        Reads the message length from the header, then the encrypted message.
        Decrypts and parses the JSON string.

        Returns:
            A dictionary representing the parsed message, or None on error.
        """
        if not self.socket:
            print("Error: Not connected to any server.")
            return None
        try:
            # Receive the message length header
            raw_msglen = self.socket.recv(MSG_LENGTH_HEADER_SIZE)
            if not raw_msglen:
                print("Connection closed by server while receiving message length.")
                return None
            
            msglen = struct.unpack('>I', raw_msglen)[0]

            # Receive the full encrypted message
            encrypted_message = b''
            while len(encrypted_message) < msglen:
                chunk = self.socket.recv(min(msglen - len(encrypted_message), self.buffer_size))
                if not chunk:
                    print("Connection closed by server while receiving message body.")
                    return None
                encrypted_message += chunk
            
            decrypted_data = decrypt_data(encrypted_message, self.shared_key)
            if decrypted_data is None:
                print("Failed to decrypt message from server.")
                return None
            
            message = json.loads(decrypted_data.decode('utf-8'))
            # print(f"Received message: Type={message.get('type')}, Payload Size (Decrypted)={len(decrypted_data)}")
            return message
        except socket.error as e:
            print(f"Socket error receiving message: {e}")
            return None
        except (json.JSONDecodeError, struct.error, UnicodeDecodeError) as e:
            print(f"Error processing received message: {e}")
            return None
        except Exception as e:
            print(f"Unexpected error receiving message: {e}")
            return None

    def send_file(self, filepath: str) -> bool:
        """
        Sends a file securely to the server.

        Args:
            filepath: The path to the file to be sent.

        Returns:
            True if the file was sent successfully, False otherwise.
        """
        if not os.path.exists(filepath):
            print(f"Error: File not found at {filepath}")
            return False
        if not self.socket:
            print("Error: Not connected to server for sending file.")
            return False

        try:
            filename = os.path.basename(filepath)
            with open(filepath, "rb") as f:
                file_data = f.read()
            
            print(f"Initiating file transfer for: {filename}, Size: {len(file_data)} bytes")
            if not self._send_message("file_transfer_start", {"filename": filename, "size": len(file_data)}):
                return False

            ack = self._receive_message()
            if not (ack and ack.get("type") == "ack_file_transfer_start" and ack.get("payload", {}).get("filename") == filename):
                print(f"Server did not acknowledge start of file transfer for {filename}. Ack: {ack}")
                return False
            print(f"Server acknowledged start of transfer for {filename}.")

            # Send file in chunks
            chunk_size = self.buffer_size - 512 # Account for encryption overhead and JSON structure
            offset = 0
            while offset < len(file_data):
                chunk = file_data[offset:offset + chunk_size]
                # print(f"Sending chunk for {filename}: Offset={offset}, Size={len(chunk)}")
                if not self._send_message("file_chunk", {"filename": filename, "data": base64.b64encode(chunk).decode('utf-8')}):
                    print(f"Failed to send a chunk for {filename}.")
                    return False
                offset += len(chunk)
            
            print(f"All chunks sent for {filename}.")
            if not self._send_message("file_transfer_end", {"filename": filename}):
                print(f"Failed to send file_transfer_end for {filename}.")
                return False

            ack_end = self._receive_message()
            if not (ack_end and ack_end.get("type") == "ack_file_transfer_end" and ack_end.get("payload", {}).get("filename") == filename):
                print(f"Server did not acknowledge end of file transfer for {filename}. Ack: {ack_end}")
                return False
            
            print(f"File '{filename}' sent successfully and acknowledged by server.")
            return True
        except FileNotFoundError:
            print(f"Error: File not found at {filepath}")
            return False
        except Exception as e:
            print(f"An error occurred during file sending: {e}")
            return False

    def receive_data(self, save_path: str | None = None) -> str | dict | None:
        """
        Receives data from the server, which could be a file or a command response.

        If `save_path` is provided and a file is being received, it saves the file there.
        This method handles messages like "file_transfer_start", "file_chunk", "file_transfer_end",
        or a direct "command_response" or other types.

        Args:
            save_path: Optional directory path to save incoming files.
                       If None, file content might be returned or handled differently.

        Returns:
            - If a file is received and `save_path` is specified: path to the saved file.
            - If a command response or other data: the parsed message payload (dict).
            - None if an error occurs or no specific data is identified.
        """
        message = self._receive_message()
        if not message:
            return None

        msg_type = message.get("type")
        payload = message.get("payload", {})

        if msg_type == "file_transfer_start":
            filename = payload.get("filename")
            filesize = payload.get("size")
            if not filename or filesize is None:
                print("Invalid file_transfer_start message from server.")
                return None

            if save_path:
                if not os.path.isdir(save_path):
                    try:
                        os.makedirs(save_path, exist_ok=True)
                    except OSError as e:
                        print(f"Error creating directory {save_path}: {e}")
                        self._send_message("ack_file_transfer_start", {"filename": filename, "status": "error", "detail": "Cannot create save directory"})
                        return None
                
                filepath = os.path.join(save_path, filename)
                self._receiving_file_info = {
                    "filepath": filepath,
                    "file_obj": open(filepath, "wb"),
                    "remaining_bytes": filesize,
                    "filename": filename
                }
                print(f"Server initiated file transfer for {filename}. Saving to {filepath}")
                self._send_message("ack_file_transfer_start", {"filename": filename, "status": "ready"})
                # Now wait for chunks
                return self.receive_data(save_path) # Recursive call to handle next messages (chunks)
            else:
                print(f"Server wants to send file {filename}, but no save_path provided.")
                # Acknowledge but indicate no save path (server might then not send chunks)
                self._send_message("ack_file_transfer_start", {"filename": filename, "status": "error", "detail": "No save path provided by client"})
                return payload # Return metadata

        elif msg_type == "file_chunk":
            if not self._receiving_file_info:
                print("Received file_chunk without active file reception.")
                return None
            
            file_info = self._receiving_file_info
            try:
                chunk_data = base64.b64decode(payload.get("data", "").encode('utf-8'))
                file_info["file_obj"].write(chunk_data)
                file_info["remaining_bytes"] -= len(chunk_data)
                # print(f"Received chunk for {file_info['filename']}, {file_info['remaining_bytes']} bytes remaining.")
                if file_info["remaining_bytes"] <= 0: # Check if all data is received
                    # This might be handled by file_transfer_end instead
                    pass
                return self.receive_data(save_path) # Wait for more chunks or end message
            except Exception as e:
                print(f"Error writing file chunk for {file_info['filename']}: {e}")
                file_info["file_obj"].close()
                os.remove(file_info["filepath"]) # Clean up partial file
                self._receiving_file_info = {}
                return None


        elif msg_type == "file_transfer_end":
            if not self._receiving_file_info or self._receiving_file_info.get("filename") != payload.get("filename"):
                print("Received file_transfer_end for unexpected/unknown file.")
                return None

            file_info = self._receiving_file_info
            file_info["file_obj"].close()
            saved_filepath = file_info["filepath"]
            print(f"File '{file_info['filename']}' received successfully at {saved_filepath}.")
            self._send_message("ack_file_transfer_end", {"filename": file_info['filename'], "status": "success"})
            self._receiving_file_info = {} # Clear state
            return saved_filepath

        elif msg_type == "command_response" or msg_type == "ack_command":
            print(f"Received response: {payload}")
            return payload
        
        else:
            print(f"Received unhandled message type '{msg_type}': {payload}")
            return payload # Return the payload for other types

    def send_command(self, command: str, params: dict | None = None) -> dict | None:
        """
        Sends a command to the server and waits for a response.

        Args:
            command: The name of the command to send.
            params: An optional dictionary of parameters for the command.

        Returns:
            The server's response payload as a dictionary, or None on error.
        """
        print(f"Sending command: {command} with params: {params or {}}")
        if not self._send_message("command", {"command_name": command, "params": params or {}}):
            return None
        
        # The response might be a direct command_response or involve file transfer
        # For simplicity, this version assumes a direct response.
        # More complex scenarios (like command triggering server to send file) need robust handling in listen_for_commands
        response = self._receive_message() 
        if response and response.get("type") == "command_response":
            return response.get("payload")
        elif response:
            print(f"Unexpected response type to command: {response.get('type')}")
            # It could be the start of a file transfer, handle if necessary
            # For now, just return the raw response if not 'command_response'
            return response 
        return None

    def listen_for_commands(self, download_dir: str = "client_downloads"):
        """
        Listens for incoming messages from the server (commands or file requests).
        This is a blocking call that runs a loop.

        Args:
            download_dir: Directory to save files requested by the server.
        """
        if not self.socket:
            print("Cannot listen, not connected.")
            return
        
        if not os.path.exists(download_dir):
            os.makedirs(download_dir, exist_ok=True)

        print("Client is now listening for commands from the server...")
        try:
            while True:
                message = self._receive_message()
                if not message:
                    print("Connection lost or error during receive. Stopping listener.")
                    break 
                
                msg_type = message.get("type")
                payload = message.get("payload", {})

                if msg_type == "command":
                    command_name = payload.get("command_name")
                    params = payload.get("params", {})
                    print(f"Received command from server: '{command_name}' with params: {params}")
                    # Placeholder for actual command execution
                    # In a real app, this would dispatch to command handlers
                    ack_payload = {"status": "received", "command": command_name, "detail": "Command processed by client (placeholder)."}
                    self._send_message("ack_command", ack_payload)
                    print(f"Acknowledged command: {command_name}")

                elif msg_type == "request_file":
                    filepath_on_client = payload.get("filepath")
                    if filepath_on_client:
                        print(f"Server requested file: {filepath_on_client}")
                        if os.path.exists(filepath_on_client):
                            self.send_file(filepath_on_client)
                        else:
                            print(f"File '{filepath_on_client}' not found on client. Notifying server.")
                            self._send_message("error_request_file", {"filepath": filepath_on_client, "detail": "File not found on client."})
                    else:
                        print("Invalid 'request_file' message from server (no filepath).")
                
                elif msg_type in ["file_transfer_start", "file_chunk", "file_transfer_end"]:
                    # This means server is sending a file unprompted by a client command
                    # (e.g. after server-side `send_file_to_client`)
                    print(f"Receiving server-initiated file transfer: Type={msg_type}")
                    # Use receive_data to handle these messages.
                    # The state (_receiving_file_info) is managed within receive_data
                    saved_item = self.receive_data(save_path=download_dir)
                    if saved_item:
                        print(f"Server-initiated file operation resulted in: {saved_item}")
                    else:
                        print(f"Server-initiated file operation (type: {msg_type}) did not complete successfully via receive_data.")


                else:
                    print(f"Client received unhandled message type '{msg_type}': {payload}")

        except KeyboardInterrupt:
            print("Listener interrupted by user.")
        except Exception as e:
            print(f"Error in client listener loop: {e}")
        finally:
            print("Client listener stopped.")
            self.disconnect()


class SecureFileTransferServer:
    """
    Server for secure file transfers and command execution.

    Listens for client connections, handles encrypted messages,
    file reception/sending, and command processing.
    """
    def __init__(self, host: str, port: int, shared_key: str, buffer_size: int = 4096, download_dir: str = "server_downloads"):
        """
        Initializes the SecureFileTransferServer.

        Args:
            host: The server's hostname or IP address to bind to.
            port: The port number to listen on.
            shared_key: The base64 encoded Fernet key for encryption.
            buffer_size: The size of the buffer for receiving data.
            download_dir: Directory to save files received from clients.
        """
        self.host = host
        self.port = port
        self.shared_key = shared_key
        self.buffer_size = buffer_size
        self.download_dir = download_dir
        self.server_socket: socket.socket | None = None
        # For simplicity, this example handles one client at a time in handle_client.
        # For multiple concurrent clients, client_connections would need thread-safe management.
        self.client_connections = {} # Stores conn: {addr: address, receiving_file_info: {}}
        
        if not os.path.exists(self.download_dir):
            try:
                os.makedirs(self.download_dir)
                print(f"Created download directory: {self.download_dir}")
            except OSError as e:
                # This is a critical error for the server's functionality
                raise OSError(f"Could not create download directory {self.download_dir}: {e}")


    def _send_message(self, conn: socket.socket, message_type: str, payload: dict) -> bool:
        """
        Constructs, encrypts, and sends a message to a specific client.
        (Identical to client's _send_message but takes a connection object)
        """
        try:
            message_data = {"type": message_type, "payload": payload}
            json_string = json.dumps(message_data)
            encrypted_message = encrypt_data(json_string.encode('utf-8'), self.shared_key)
            
            message_length_header = struct.pack('>I', len(encrypted_message))
            conn.sendall(message_length_header)
            conn.sendall(encrypted_message)
            # print(f"Sent message to {conn.getpeername()}: Type={message_type}, Payload Size (Encrypted)={len(encrypted_message)}")
            return True
        except socket.error as e:
            print(f"Socket error sending message to {conn.getpeername()}: {e}")
            return False
        except Exception as e:
            print(f"Error sending message to {conn.getpeername()}: {e}")
            return False

    def _receive_message(self, conn: socket.socket) -> dict | None:
        """
        Receives, decrypts, and parses a message from a specific client.
        (Identical to client's _receive_message but takes a connection object)
        """
        try:
            raw_msglen = conn.recv(MSG_LENGTH_HEADER_SIZE)
            if not raw_msglen:
                # print(f"Connection closed by {conn.getpeername()} while receiving message length.")
                return None
            msglen = struct.unpack('>I', raw_msglen)[0]

            encrypted_message = b''
            while len(encrypted_message) < msglen:
                chunk = conn.recv(min(msglen - len(encrypted_message), self.buffer_size))
                if not chunk:
                    # print(f"Connection closed by {conn.getpeername()} while receiving message body.")
                    return None
                encrypted_message += chunk
            
            decrypted_data = decrypt_data(encrypted_message, self.shared_key)
            if decrypted_data is None:
                print(f"Failed to decrypt message from {conn.getpeername()}.")
                return None
            
            message = json.loads(decrypted_data.decode('utf-8'))
            # print(f"Received message from {conn.getpeername()}: Type={message.get('type')}, Payload Size (Decrypted)={len(decrypted_data)}")
            return message
        except socket.error: # Catch specific socket error if client disconnects abruptly
            # print(f"Socket error (likely client disconnected) from {conn.getpeername()}: {e}")
            return None # Indicate client disconnected or error
        except (json.JSONDecodeError, struct.error, UnicodeDecodeError) as e:
            print(f"Error processing message from {conn.getpeername()}: {e}")
            return None
        except Exception as e:
            print(f"Unexpected error receiving message from {conn.getpeername()}: {e}")
            return None


    def start(self) -> bool:
        """
        Starts the server, binds to the host/port, and begins listening.

        Returns:
            True if the server started successfully, False otherwise.
        """
        try:
            self.server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            self.server_socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            self.server_socket.bind((self.host, self.port))
            self.server_socket.listen(5) # Listen for up to 5 queued connections
            print(f"Server started on {self.host}:{self.port}, listening for connections...")
            return True
        except socket.error as e:
            print(f"Error starting server: {e}")
            self.server_socket = None
            return False
        except Exception as e: # Catch any other unexpected errors
            print(f"Unexpected error starting server: {e}")
            self.server_socket = None
            return False

    def accept_connection(self) -> tuple[socket.socket, tuple[str, int]] | None:
        """
        Accepts a new client connection.

        Returns:
            A tuple (conn, addr) if a connection is accepted, None otherwise.
        """
        if not self.server_socket:
            print("Server not started. Cannot accept connections.")
            return None
        try:
            conn, addr = self.server_socket.accept()
            print(f"Accepted connection from {addr[0]}:{addr[1]}")
            # Initialize client state
            self.client_connections[conn] = {"addr": addr, "receiving_file_info": {}}
            return conn, addr
        except socket.error as e:
            print(f"Error accepting connection: {e}")
            return None

    def handle_client(self, conn: socket.socket, addr: tuple[str, int]):
        """
        Handles communication with a connected client in a loop.

        Args:
            conn: The client's socket connection object.
            addr: The client's address (ip, port).
        """
        print(f"Handling client {addr[0]}:{addr[1]}")
        client_state = self.client_connections.get(conn)
        if not client_state: # Should not happen if accept_connection was used
            print(f"Error: No state found for connection {addr}. Closing.")
            conn.close()
            return

        try:
            while True:
                message = self._receive_message(conn)
                if message is None:
                    print(f"Client {addr} disconnected or message error.")
                    break # Exit loop if client disconnects or error

                msg_type = message.get("type")
                payload = message.get("payload", {})

                # --- File Reception Logic ---
                if msg_type == "file_transfer_start":
                    filename = payload.get("filename")
                    filesize = payload.get("size")
                    if not filename or filesize is None:
                        print(f"Invalid file_transfer_start from {addr}.")
                        self._send_message(conn, "ack_file_transfer_start", {"filename": filename, "status": "error", "detail": "Invalid metadata"})
                        continue
                    
                    filepath = os.path.join(self.download_dir, os.path.basename(filename)) # Sanitize filename
                    try:
                        file_obj = open(filepath, "wb")
                        client_state["receiving_file_info"] = {
                            "filepath": filepath,
                            "file_obj": file_obj,
                            "remaining_bytes": filesize,
                            "filename": filename
                        }
                        print(f"Receiving file '{filename}' ({filesize} bytes) from {addr} to '{filepath}'.")
                        self._send_message(conn, "ack_file_transfer_start", {"filename": filename, "status": "ready"})
                    except IOError as e:
                        print(f"IOError preparing to receive file {filename} from {addr}: {e}")
                        self._send_message(conn, "ack_file_transfer_start", {"filename": filename, "status": "error", "detail": str(e)})
                        client_state["receiving_file_info"] = {}


                elif msg_type == "file_chunk":
                    file_info = client_state.get("receiving_file_info", {})
                    if not file_info or not file_info.get("file_obj"):
                        print(f"Received file_chunk from {addr} but not expecting file/chunk or file not open.")
                        # Optionally send an error back
                        continue
                    
                    try:
                        chunk_data_b64 = payload.get("data")
                        if chunk_data_b64 is None:
                             print(f"Received file_chunk from {addr} with no data.")
                             continue
                        chunk_data = base64.b64decode(chunk_data_b64.encode('utf-8'))
                        file_info["file_obj"].write(chunk_data)
                        file_info["remaining_bytes"] -= len(chunk_data)
                        # print(f"Wrote chunk for {file_info['filename']} from {addr}. {file_info['remaining_bytes']} left.")
                    except (TypeError, base64.binascii.Error, IOError) as e:
                        print(f"Error processing file_chunk from {addr} for {file_info.get('filename', 'unknown file')}: {e}")
                        file_info["file_obj"].close()
                        if os.path.exists(file_info["filepath"]):
                            os.remove(file_info["filepath"]) # Clean up partial file
                        client_state["receiving_file_info"] = {} # Reset state

                elif msg_type == "file_transfer_end":
                    file_info = client_state.get("receiving_file_info", {})
                    if not file_info or not file_info.get("file_obj") or file_info.get("filename") != payload.get("filename"):
                        print(f"Received file_transfer_end from {addr} for unexpected/unknown file.")
                        # Optionally send an error
                        continue

                    file_info["file_obj"].close()
                    print(f"File '{file_info['filename']}' from {addr} received successfully at '{file_info['filepath']}'.")
                    self._send_message(conn, "ack_file_transfer_end", {"filename": file_info['filename'], "status": "success"})
                    client_state["receiving_file_info"] = {} # Clear state
                
                # --- Command Handling Logic ---
                elif msg_type == "command":
                    command_name = payload.get("command_name")
                    params = payload.get("params", {})
                    print(f"Received command '{command_name}' with params {params} from {addr}.")
                    # Placeholder for actual command execution logic
                    # This would typically involve a dispatcher or a set of command handlers.
                    response_payload = {"status": "success", "detail": f"Command '{command_name}' processed by server (placeholder)."}
                    self._send_message(conn, "command_response", response_payload)
                
                elif msg_type == "ack_command": # Client acknowledging a server-sent command
                    print(f"Client {addr} acknowledged command: {payload}")

                elif msg_type == "error_request_file": # Client reporting error for a server file request
                     print(f"Client {addr} reported error for requested file: {payload.get('filepath')}, Detail: {payload.get('detail')}")

                else:
                    print(f"Received unhandled message type '{msg_type}' from {addr}: {payload}")
                    # self._send_message(conn, "error", {"detail": f"Unknown message type: {msg_type}"})

        except socket.error as e:
            print(f"Socket error with client {addr}: {e}")
        except Exception as e:
            print(f"Unexpected error handling client {addr}: {e}")
        finally:
            print(f"Closing connection with client {addr}.")
            if conn in self.client_connections:
                # Clean up any open file handles if client disconnected abruptly during transfer
                file_info = self.client_connections[conn].get("receiving_file_info", {})
                if file_info and file_info.get("file_obj") and not file_info["file_obj"].closed:
                    file_info["file_obj"].close()
                    print(f"Closed open file {file_info.get('filepath')} due to client disconnect.")
                    # Consider removing partial file: os.remove(file_info["filepath"])
                del self.client_connections[conn]
            try:
                conn.close()
            except socket.error:
                pass # Socket might already be closed

    def send_file_to_client(self, conn: socket.socket, filepath: str) -> bool:
        """
        Sends a file from the server to a connected client.

        Args:
            conn: The client's socket connection object.
            filepath: The path to the file on the server to send.

        Returns:
            True if the file was sent successfully, False otherwise.
        """
        if not os.path.exists(filepath):
            print(f"Error: File not found at {filepath} on server.")
            self._send_message(conn, "error_file_transfer", {"filename": os.path.basename(filepath), "detail": "File not found on server"})
            return False
        
        client_addr = self.client_connections.get(conn, {}).get("addr", "Unknown Client")

        try:
            filename = os.path.basename(filepath)
            with open(filepath, "rb") as f:
                file_data = f.read()
            
            print(f"Initiating file transfer to client {client_addr} for: {filename}, Size: {len(file_data)} bytes")
            if not self._send_message(conn, "file_transfer_start", {"filename": filename, "size": len(file_data)}):
                return False

            ack = self._receive_message(conn)
            if not (ack and ack.get("type") == "ack_file_transfer_start" and ack.get("payload", {}).get("filename") == filename):
                print(f"Client {client_addr} did not acknowledge start of file transfer for {filename}. Ack: {ack}")
                return False
            print(f"Client {client_addr} acknowledged start of transfer for {filename}.")

            chunk_size = self.buffer_size - 512 
            offset = 0
            while offset < len(file_data):
                chunk = file_data[offset:offset + chunk_size]
                if not self._send_message(conn, "file_chunk", {"filename": filename, "data": base64.b64encode(chunk).decode('utf-8')}):
                    print(f"Failed to send a chunk for {filename} to {client_addr}.")
                    return False
                offset += len(chunk)
            
            if not self._send_message(conn, "file_transfer_end", {"filename": filename}):
                print(f"Failed to send file_transfer_end for {filename} to {client_addr}.")
                return False

            ack_end = self._receive_message(conn)
            if not (ack_end and ack_end.get("type") == "ack_file_transfer_end" and ack_end.get("payload", {}).get("filename") == filename):
                print(f"Client {client_addr} did not acknowledge end of file transfer for {filename}. Ack: {ack_end}")
                return False
            
            print(f"File '{filename}' sent successfully to client {client_addr} and acknowledged.")
            return True
        except FileNotFoundError: # Should be caught by os.path.exists, but good practice
            print(f"Error: File not found at {filepath}")
            self._send_message(conn, "error_file_transfer", {"filename": os.path.basename(filepath), "detail": "File not found on server during send"})
            return False
        except Exception as e:
            print(f"An error occurred sending file to {client_addr}: {e}")
            # Attempt to notify client of error if possible
            try:
                self._send_message(conn, "error_file_transfer", {"filename": os.path.basename(filepath), "detail": str(e)})
            except:
                pass # If sending error message fails, nothing more to do
            return False

    def request_file_from_client(self, conn: socket.socket, filepath_on_client: str) -> str | None:
        """
        Requests a file from a connected client.
        The server then needs to handle the incoming file via `handle_client` logic.

        Args:
            conn: The client's socket connection object.
            filepath_on_client: The path of the file on the client's machine.

        Returns:
            The path to the downloaded file on the server if successful, None otherwise.
            Note: This method initiates the request; actual file reception happens in `handle_client`.
        """
        client_addr = self.client_connections.get(conn, {}).get("addr", "Unknown Client")
        print(f"Requesting file '{filepath_on_client}' from client {client_addr}.")
        if not self._send_message(conn, "request_file", {"filepath": filepath_on_client}):
            print(f"Failed to send file request for '{filepath_on_client}' to {client_addr}.")
            return None
        
        # After this, the server's handle_client method will receive file_transfer_start, chunks, etc.
        # This method doesn't wait for the file itself, only sends the request.
        # To confirm, we might wait for an ack like "ack_request_file" or the actual "file_transfer_start"
        # For simplicity, we assume the client will respond with file transfer messages handled by handle_client.
        print(f"File request for '{filepath_on_client}' sent to {client_addr}. Server will now listen for file.")
        # A more robust implementation might return a future or use a callback
        # to signal when the file is actually received. For now, it's fire-and-forget-ish.
        # The actual file path will be determined when handle_client processes it.
        return f"Request sent. File will be saved to {self.download_dir} if client complies."


    def send_command_to_client(self, conn: socket.socket, command: str, params: dict | None = None) -> dict | None:
        """
        Sends a command to a specific client and waits for an acknowledgment/response.

        Args:
            conn: The client's socket connection object.
            command: The name of the command to send.
            params: An optional dictionary of parameters for the command.

        Returns:
            The client's response payload as a dictionary (from "ack_command"), or None on error.
        """
        client_addr = self.client_connections.get(conn, {}).get("addr", "Unknown Client")
        print(f"Sending command '{command}' to client {client_addr} with params: {params or {}}")
        if not self._send_message(conn, "command", {"command_name": command, "params": params or {}}):
            return None
        
        # Wait for client's acknowledgment
        response = self._receive_message(conn)
        if response and response.get("type") == "ack_command" and response.get("payload", {}).get("command") == command:
            print(f"Client {client_addr} acknowledged command '{command}'. Response: {response.get('payload')}")
            return response.get("payload")
        else:
            print(f"Client {client_addr} did not properly acknowledge command '{command}'. Received: {response}")
            return None

    def receive_file_securely(self, conn: socket.socket, expected_filename: str | None = None, save_dir_override: str | None = None) -> str | None:
        """
        Dedicated method to receive a single file from a client.
        Assumes the client has been prompted (e.g., by request_file_from_client) 
        and will initiate sending the file. Handles file_transfer_start, 
        file_chunk, and file_transfer_end messages for one file.

        Args:
            conn: The client socket connection.
            expected_filename: The basename of the file expected from the client. 
                               If provided, the received filename must match.
            save_dir_override: If provided, save the file to this directory instead of self.download_dir.

        Returns:
            The full path to the saved file if successful, None otherwise.
        """
        client_state = self.client_connections.get(conn)
        if not client_state:
            peername = "Unknown (connection not in client_connections)"
            try:
                peername = conn.getpeername()
            except: pass
            print(f"Error: No state found for connection {peername} during receive_file_securely.")
            return None
        
        client_addr = client_state.get("addr", "Unknown Address")
        
        # Ensure any previous partial state for this connection is cleared.
        # This is important if this method is called and a previous attempt failed uncleanly.
        client_state["receiving_file_info"] = {}
        
        file_transfer_active = False
        saved_filepath = None
        
        # Timeout for waiting for the initial file_transfer_start message
        # You might want to make this configurable.
        initial_timeout_seconds = 30 
        time_waited = 0
        wait_interval = 0.1 

        try:
            print(f"[{client_addr}] Waiting for file transfer to start (expected: {expected_filename or 'any'})...")
            # Loop to specifically catch the start of a file transfer
            while not file_transfer_active:
                if time_waited >= initial_timeout_seconds:
                    print(f"[{client_addr}] Timeout: Did not receive 'file_transfer_start' within {initial_timeout_seconds}s.")
                    return None

                # Non-blocking check or use select might be better in a fully async server,
                # but for one-at-a-time driven by ReconServerApp, a short timeout on recv is okay.
                # For simplicity, _receive_message already has its own internal timeout for recv.
                # We are just adding a loop for the *first* message.
                conn.settimeout(wait_interval) # Short timeout for polling
                message = None
                try:
                    message = self._receive_message(conn)
                except socket.timeout:
                    time_waited += wait_interval
                    continue # Continue waiting for file_transfer_start
                finally:
                    conn.settimeout(None) # Reset to blocking or global default for subsequent receives

                if message is None: # Client disconnected or error in _receive_message
                    print(f"[{client_addr}] Connection lost or error while waiting for 'file_transfer_start'.")
                    return None # Cleanup handled by finally block if needed

                msg_type = message.get("type")
                payload = message.get("payload", {})

                if msg_type == "file_transfer_start":
                    actual_filename = payload.get("filename")
                    filesize = payload.get("size")

                    if not actual_filename or filesize is None:
                        print(f"[{client_addr}] Invalid 'file_transfer_start': missing filename or size. Payload: {payload}")
                        self._send_message(conn, "ack_file_transfer_start", {"filename": actual_filename, "status": "error", "detail": "Invalid metadata in file_transfer_start"})
                        return None

                    if expected_filename and os.path.basename(actual_filename) != os.path.basename(expected_filename):
                        print(f"[{client_addr}] Received 'file_transfer_start' for '{actual_filename}', but expected '{expected_filename}'.")
                        self._send_message(conn, "ack_file_transfer_start", {"filename": actual_filename, "status": "error", "detail": f"Unexpected filename. Expected {expected_filename}."})
                        return None
                    
                    # Determine the target directory for saving the file
                    target_save_dir = self.download_dir
                    if save_dir_override:
                        target_save_dir = save_dir_override
                    
                    # Ensure the target directory exists
                    try:
                        os.makedirs(target_save_dir, exist_ok=True)
                    except OSError as e_mkdir:
                        print(f"[{client_addr}] Error creating directory {target_save_dir}: {e_mkdir}")
                        self._send_message(conn, "ack_file_transfer_start", {"filename": actual_filename, "status": "error", "detail": f"Server cannot create save directory: {e_mkdir}"})
                        return None

                    filepath = os.path.join(target_save_dir, os.path.basename(actual_filename))
                    try:
                        file_obj = open(filepath, "wb")
                        client_state["receiving_file_info"] = {
                            "filepath": filepath,
                            "file_obj": file_obj,
                            "remaining_bytes": filesize,
                            "filename": actual_filename # Store the actual filename from client
                        }
                        file_transfer_active = True # Crucial: set state to active
                        print(f"[{client_addr}] Receiving '{actual_filename}' ({filesize} bytes) to '{filepath}'.")
                        self._send_message(conn, "ack_file_transfer_start", {"filename": actual_filename, "status": "ready"})
                    except IOError as e:
                        print(f"[{client_addr}] IOError opening file '{filepath}' for write: {e}")
                        self._send_message(conn, "ack_file_transfer_start", {"filename": actual_filename, "status": "error", "detail": f"Server IOError: {e}"})
                        return None
                elif msg_type == "error": # Client might immediately send an error
                    print(f"[{client_addr}] Client sent error: {payload.get('detail')}")
                    return None
                else:
                    print(f"[{client_addr}] Unexpected message type '{msg_type}' while waiting for 'file_transfer_start'. Discarding.")
                    # Optionally, send an error to client if this is strictly disallowed.
                    # Loop again to wait for file_transfer_start, but increment timeout.
                    time_waited += wait_interval # Count this as part of the wait time.


            # File transfer is active, now process chunks and end
            while file_transfer_active: # This loop processes subsequent messages (chunk, end)
                message = self._receive_message(conn) # This will now block until a message or timeout in _receive_message
                if message is None:
                    print(f"[{client_addr}] Connection lost or error during file transfer of '{client_state['receiving_file_info'].get('filename', 'unknown file')}'.")
                    # Cleanup is handled in finally
                    return None 

                msg_type = message.get("type")
                payload = message.get("payload", {})
                current_file_info = client_state.get("receiving_file_info", {}) # Should always exist if file_transfer_active

                if msg_type == "file_chunk":
                    if not current_file_info or not current_file_info.get("file_obj"):
                        print(f"[{client_addr}] Received 'file_chunk' but not in a valid file receiving state. Payload: {payload}")
                        # This is a protocol error.
                        self._send_message(conn, "error", {"detail": "Server not ready for file_chunk."})
                        return None # Cleanup in finally

                    try:
                        chunk_data_b64 = payload.get("data")
                        if chunk_data_b64 is None:
                            print(f"[{client_addr}] Received 'file_chunk' with no data for {current_file_info['filename']}.")
                            # Consider this an error or just skip? Error is safer.
                            raise ValueError("File chunk message contained no data.")
                        
                        chunk_data = base64.b64decode(chunk_data_b64.encode('utf-8'))
                        current_file_info["file_obj"].write(chunk_data)
                        current_file_info["remaining_bytes"] -= len(chunk_data)
                        # print(f"[{client_addr}] Wrote chunk for {current_file_info['filename']}. {current_file_info['remaining_bytes']} left.")
                    except (TypeError, base64.binascii.Error, ValueError, IOError) as e:
                        print(f"[{client_addr}] Error processing 'file_chunk' for {current_file_info.get('filename', 'unknown file')}: {e}")
                        self._send_message(conn, "error", {"detail": f"Server error processing chunk: {e}"})
                        # Cleanup in finally
                        return None

                elif msg_type == "file_transfer_end":
                    if not current_file_info or not current_file_info.get("file_obj"):
                        print(f"[{client_addr}] Received 'file_transfer_end' but not in a valid file receiving state. Payload: {payload}")
                        self._send_message(conn, "ack_file_transfer_end", {"filename": payload.get("filename"), "status": "error", "detail": "Server not ready for file_transfer_end"})
                        return None # Cleanup in finally

                    received_end_filename = payload.get("filename")
                    if current_file_info.get("filename") != received_end_filename:
                        print(f"[{client_addr}] 'file_transfer_end' for '{received_end_filename}', but was receiving '{current_file_info.get('filename')}'.")
                        self._send_message(conn, "ack_file_transfer_end", {"filename": received_end_filename, "status": "error", "detail": "Filename mismatch in file_transfer_end."})
                        # Cleanup in finally
                        return None
                    
                    # Check if all bytes were received (optional, but good sanity check)
                    if current_file_info.get("remaining_bytes", 0) > 0:
                        print(f"[{client_addr}] Warning: 'file_transfer_end' received for '{received_end_filename}', but {current_file_info['remaining_bytes']} bytes were still expected.")
                        # Decide if this is an error. For now, proceed but log.

                    current_file_info["file_obj"].close() # Close file object first
                    saved_filepath = current_file_info["filepath"] # Store before clearing
                    print(f"[{client_addr}] File '{saved_filepath}' received successfully.")
                    self._send_message(conn, "ack_file_transfer_end", {"filename": received_end_filename, "status": "success"})
                    
                    client_state["receiving_file_info"] = {} # Clear the state for this specific transfer
                    file_transfer_active = False # Exit the chunk processing loop
                    return saved_filepath # SUCCESS

                elif msg_type == "error": # Client might send an error during transfer
                    print(f"[{client_addr}] Client sent error during file transfer: {payload.get('detail')}")
                    # Cleanup handled in finally
                    return None
                else:
                    print(f"[{client_addr}] Unexpected message type '{msg_type}' during active file transfer. Payload: {payload}")
                    self._send_message(conn, "error", {"detail": f"Unexpected message type '{msg_type}' during file transfer."})
                    # Cleanup handled in finally
                    return None
        
        except socket.timeout: # This would be from _receive_message if it times out internally
            print(f"[{client_addr}] Socket timeout during file reception for '{client_state.get('receiving_file_info',{}).get('filename', expected_filename or 'unknown file')}'.")
            return None # Cleanup in finally
        except Exception as e:
            print(f"[{client_addr}] Unexpected exception during receive_file_securely for '{client_state.get('receiving_file_info',{}).get('filename', expected_filename or 'unknown file')}': {e}")
            import traceback
            traceback.print_exc()
            try: # Try to notify client
                self._send_message(conn, "error", {"detail": f"Unexpected server error during file reception: {str(e)}"})
            except: pass
            return None # Cleanup in finally
        finally:
            # Ensure cleanup if function exits due to error or return None prematurely
            if file_transfer_active: # Means an error occurred mid-transfer
                current_file_info = client_state.get("receiving_file_info", {})
                if current_file_info and current_file_info.get("file_obj"):
                    if not current_file_info["file_obj"].closed:
                        current_file_info["file_obj"].close()
                    # Remove partially written file
                    filepath_to_remove = current_file_info.get("filepath")
                    if filepath_to_remove and os.path.exists(filepath_to_remove):
                        try:
                            print(f"[{client_addr}] Cleaning up partially received file: {filepath_to_remove}")
                            os.remove(filepath_to_remove)
                        except OSError as e_rm:
                            print(f"[{client_addr}] Error removing partial file {filepath_to_remove}: {e_rm}")
            # Always clear the receiving state for this connection if it was used by this method
            client_state["receiving_file_info"] = {}
            conn.settimeout(None) # Reset socket timeout to default blocking if it was changed

        # Should not be reached if logic is correct (all paths should return from within try/except)
        return None


    def stop(self):
        """Closes all client connections and the server socket."""
        print("Stopping server...")
        # Close all active client connections
        # Iterate over a copy of keys if modifying dict during iteration (though del should be safe here)
        for conn in list(self.client_connections.keys()):
            try:
                addr = self.client_connections[conn]["addr"]
                print(f"Closing connection with {addr}...")
                conn.close()
            except (socket.error, KeyError) as e:
                print(f"Error closing client connection {self.client_connections.get(conn, {}).get('addr', '')}: {e}")
            finally:
                if conn in self.client_connections:
                    del self.client_connections[conn]
        
        if self.server_socket:
            try:
                self.server_socket.close()
                print("Server socket closed.")
            except socket.error as e:
                print(f"Error closing server socket: {e}")
            finally:
                self.server_socket = None
        print("Server stopped.")

if __name__ == '__main__':
    # Example Usage (for testing purposes - normally these would be in separate scripts)
    # This basic test won't work directly without threading for server and client in same script.
    # It's recommended to run the server_app.py and client_app.py in separate terminals for testing.

    print("This script defines SecureFileTransferClient and SecureFileTransferServer classes.")
    print("These classes are used by server_app.py and client_app.py.")
    print("For generating a new Fernet key (if cryptography is installed):")
    print("  python -c \"from cryptography.fernet import Fernet; print(Fernet.generate_key().decode())\"")
    
    # Example of how reconlibs.generate_key() could be used if reconlibs is in PYTHONPATH
    # and cryptography is installed.
    try:
        # This is just to demonstrate key generation; reconlibs itself is imported at the top.
        from reconlibs import generate_key as generate_fernet_key
        print(f"\nExample of generating a key using reconlibs.generate_key():")
        print(f"  A new key: {generate_fernet_key()}")
        print("  (Ensure this key is set in your recon.opts file for both client and server)")
    except ImportError:
        print("\nCould not import reconlibs.generate_key directly for example key generation.")
        print("Make sure reconlibs.py is in your Python path.")
    except Exception as e: # Catch cryptography.fernet.InvalidKey or other errors if crypto is missing
        print(f"\nNote: reconlibs.generate_key() requires 'cryptography' library.")
        print(f"  Error during example key generation: {e}")

    if 'encrypt_data' not in globals() or 'decrypt_data' not in globals() or \
       (hasattr(encrypt_data, '__doc__') and encrypt_data.__doc__.startswith("Placeholder")):
        print("\nWARNING: Using placeholder encryption/decryption functions.")
        print("Actual encryption/decryption requires reconlibs.py with the 'cryptography' library installed.")
        print("Communication will NOT be secure.")

```
