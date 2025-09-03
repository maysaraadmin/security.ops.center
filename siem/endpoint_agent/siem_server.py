"""
Simple SIEM Server for receiving logs from SIEM Endpoint Agent
"""
import json
import socket
import ssl
import threading
import logging
from datetime import datetime
from pathlib import Path

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s',
    handlers=[
        logging.FileHandler('siem_server.log'),
        logging.StreamHandler()
    ]
)
logger = logging.getLogger('siem_server')

class SIEMMessageHandler:
    def __init__(self):
        self.log_file = Path('siem_logs.jsonl')
        # Create log file if it doesn't exist
        if not self.log_file.exists():
            self.log_file.touch()
    
    def handle_message(self, data, client_address):
        """Handle incoming log messages."""
        try:
            # Try to decode as UTF-8 first, then try other common encodings if that fails
            try:
                log_entry = json.loads(data.decode('utf-8'))
            except UnicodeDecodeError:
                # Try with different encodings
                for encoding in ['utf-8-sig', 'latin-1', 'cp1252', 'cp1256']:
                    try:
                        decoded_data = data.decode(encoding)
                        log_entry = json.loads(decoded_data)
                        logger.info(f"Successfully decoded message using {encoding} encoding")
                        break
                    except (UnicodeDecodeError, json.JSONDecodeError) as e:
                        logger.debug(f"Failed to decode with {encoding}: {str(e)}")
                        continue
                else:
                    # Log the raw bytes for debugging
                    logger.error(f"Could not decode message with any supported encoding. First 50 bytes: {data[:50]}")
                    raise ValueError("Could not decode message with any supported encoding")
            
            # Add metadata
            log_entry['received_at'] = datetime.utcnow().isoformat()
            log_entry['source_ip'] = client_address[0]
            
            # Save to file
            with open(self.log_file, 'a') as f:
                f.write(json.dumps(log_entry) + '\n')
            
            logger.info(f"Received log from {client_address[0]}: {log_entry.get('message', 'No message')}")
            return True
            
        except json.JSONDecodeError:
            logger.error(f"Invalid JSON received from {client_address}")
            return False
        except Exception as e:
            logger.error(f"Error processing message: {e}", exc_info=True)
            return False

class SIEMManager:
    def __init__(self, host='0.0.0.0', port=10514, use_tls=False):
        self.host = host
        self.port = port
        self.use_tls = use_tls
        self.running = False
        self.message_handler = SIEMMessageHandler()
        self.log_file = Path('siem_logs.jsonl')
        
        # Create log file if it doesn't exist
        if not self.log_file.exists():
            self.log_file.touch()
        
        # SSL context for secure connections
        self.ssl_context = None
        if self.use_tls:
            self.ssl_context = ssl.create_default_context(ssl.Purpose.CLIENT_AUTH)
            # In production, you should use proper certificates
            self.ssl_context.check_hostname = False
            self.ssl_context.verify_mode = ssl.CERT_NONE
    
    def handle_connection(self, client_socket, client_address):
        """Handle a client connection with the custom protocol."""
        try:
            client_socket.settimeout(10.0)  # Increased timeout for better reliability
            
            # First, read the number of log entries (4 bytes, big-endian)
            num_entries_data = client_socket.recv(4)
            if not num_entries_data or len(num_entries_data) != 4:
                logger.warning(f"Invalid number of entries data from {client_address}")
                return
                
            num_entries = int.from_bytes(num_entries_data, byteorder='big')
            if num_entries <= 0 or num_entries > 1000:  # Sanity check
                logger.warning(f"Invalid number of entries: {num_entries} from {client_address}")
                return
                
            logger.info(f"Expecting {num_entries} log entries from {client_address}")
            
            for _ in range(num_entries):
                # Read the length of the JSON data (4 bytes, big-endian)
                length_data = client_socket.recv(4)
                if not length_data or len(length_data) != 4:
                    logger.warning(f"Invalid message length data from {client_address}")
                    break
                    
                length = int.from_bytes(length_data, byteorder='big')
                if length <= 0 or length > 10 * 1024 * 1024:  # 10MB max
                    logger.warning(f"Invalid message length {length} from {client_address}")
                    break
                
                # Read the actual JSON data
                chunks = []
                bytes_received = 0
                while bytes_received < length:
                    try:
                        chunk = client_socket.recv(min(4096, length - bytes_received))
                        if not chunk:
                            logger.warning(f"Connection closed by client {client_address} while reading message")
                            return
                        chunks.append(chunk)
                        bytes_received += len(chunk)
                    except socket.timeout:
                        logger.warning(f"Timeout reading message data from {client_address}")
                        return
                    except Exception as e:
                        logger.error(f"Error reading message from {client_address}: {e}")
                        return
                
                try:
                    data = b''.join(chunks)
                    log_entry = json.loads(data.decode('utf-8'))
                    log_entry['received_at'] = datetime.utcnow().isoformat()
                    log_entry['source_ip'] = client_address[0]
                    
                    # Save to file
                    with open(self.log_file, 'a', encoding='utf-8') as f:
                        f.write(json.dumps(log_entry) + '\n')
                    
                    logger.debug(f"Received log from {client_address[0]}: {log_entry.get('message', 'No message')}")
                    
                    # Send acknowledgment
                    try:
                        client_socket.sendall(b'\x01')
                    except Exception as e:
                        logger.error(f"Failed to send ACK to {client_address}: {e}")
                        return
                        
                except json.JSONDecodeError as e:
                    logger.error(f"Invalid JSON data from {client_address}: {e}")
                    try:
                        client_socket.sendall(b'\x00')  # NAK for invalid JSON
                    except:
                        pass
                    break
                except Exception as e:
                    logger.error(f"Error processing log entry from {client_address}: {e}", exc_info=True)
                    try:
                        client_socket.sendall(b'\x00')  # NAK for other errors
                    except:
                        pass
                    break
                        
        except socket.timeout:
            logger.warning(f"Connection timeout with {client_address}")
        except Exception as e:
            logger.error(f"Error handling connection from {client_address}: {e}", exc_info=True)
        finally:
            try:
                client_socket.close()
            except:
                pass
    
    def start(self):
        """Start the SIEM server."""
        self.running = True
        
        # Create TCP socket
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        sock.settimeout(1)  # Add timeout to allow checking self.running
        sock.bind((self.host, self.port))
        sock.listen(5)
        
        logger.info(f"SIEM Server started on {self.host}:{self.port} (TLS: {self.use_tls})")
        
        try:
            while self.running:
                try:
                    client_socket, client_address = sock.accept()
                    client_socket.settimeout(5)  # Set timeout for client operations
                    logger.info(f"Connection from {client_address}")
                    
                    # Handle client connection in a new thread
                    client_thread = threading.Thread(
                        target=self.handle_connection,
                        args=(client_socket, client_address)
                    )
                    client_thread.daemon = True
                    client_thread.start()
                    
                except socket.timeout:
                    # This is expected, just continue the loop
                    continue
                except Exception as e:
                    logger.error(f"Error in server loop: {e}", exc_info=True)
                    time.sleep(1)  # Prevent tight loop on error
                
        except KeyboardInterrupt:
            logger.info("Shutting down SIEM server...")
        except Exception as e:
            logger.error(f"Fatal error in server: {e}", exc_info=True)
        finally:
            sock.close()
            self.running = False
            logger.info("SIEM Server stopped")

if __name__ == "__main__":
    import argparse
    
    parser = argparse.ArgumentParser(description='SIEM Server for receiving logs from endpoint agents')
    parser.add_argument('--host', default='0.0.0.0', help='Host to bind to (default: 0.0.0.0)')
    parser.add_argument('--port', type=int, default=10514, help='Port to listen on (default: 10514)')
    parser.add_argument('--tls', action='store_true', help='Enable TLS (requires cert.pem and key.pem)')
    
    args = parser.parse_args()
    
    siem = SIEMManager(host=args.host, port=args.port, use_tls=args.tls)
    siem.start()
