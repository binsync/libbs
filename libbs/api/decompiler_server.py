import logging
import pickle
import socket
import struct
import threading
import time
import tempfile
import os
from typing import Optional, Dict, Any, List
from pathlib import Path

from libbs.api.decompiler_interface import DecompilerInterface

_l = logging.getLogger(__name__)


class SocketProtocol:
    """Helper class for socket protocol message framing"""
    
    @staticmethod
    def send_message(sock: socket.socket, data: Any) -> None:
        """Send a pickled message with length prefix"""
        try:
            pickled_data = pickle.dumps(data)
            msg_len = len(pickled_data)
            
            # Send 4-byte length prefix
            sock.sendall(struct.pack('!I', msg_len))
            # Send pickled data
            sock.sendall(pickled_data)
        except Exception as e:
            _l.error(f"Failed to send message (pickle.dumps): {e}")
            _l.error(f"Data type: {type(data)}")
            if hasattr(data, '__dict__'):
                _l.error(f"Data dict: {data.__dict__}")
            raise
    
    @staticmethod
    def recv_message(sock: socket.socket) -> Any:
        """Receive a pickled message with length prefix"""
        try:
            # Receive 4-byte length prefix
            len_data = sock.recv(4)
            if len(len_data) != 4:
                raise ConnectionError("Failed to receive message length")
            
            msg_len = struct.unpack('!I', len_data)[0]
            
            # Receive the pickled data
            pickled_data = b''
            while len(pickled_data) < msg_len:
                chunk = sock.recv(msg_len - len(pickled_data))
                if not chunk:
                    raise ConnectionError("Connection closed while receiving message")
                pickled_data += chunk
            
            return pickle.loads(pickled_data)
        except Exception as e:
            _l.error(f"Failed to receive message (pickle.loads): {e}")
            _l.error(f"Received {len(pickled_data)} bytes of pickle data")
            raise


class SocketServerHandler:
    """Handler for individual client connections"""
    
    def __init__(self, deci: DecompilerInterface):
        self.deci = deci
        self._light_caches = {}
        self._cache_lock = threading.Lock()
        self._cache_ttl = 10.0
    
    def handle_client(self, client_socket: socket.socket, addr: str):
        """Handle a client connection"""
        _l.info(f"Client connected: {addr}")
        
        try:
            while True:
                try:
                    request = SocketProtocol.recv_message(client_socket)
                    response = self._process_request(request)
                    SocketProtocol.send_message(client_socket, response)
                except ConnectionError:
                    # Client disconnected
                    break
                except Exception as e:
                    # Send error response
                    error_response = {"error": str(e), "type": type(e).__name__}
                    try:
                        SocketProtocol.send_message(client_socket, error_response)
                    except:
                        break
        finally:
            client_socket.close()
            _l.info(f"Client disconnected: {addr}")
    
    def _process_request(self, request: Dict[str, Any]) -> Any:
        """Process a client request and return response"""
        request_type = request.get("type")
        
        if request_type == "server_info":
            return {
                "name": "LibBS DecompilerServer (AF_UNIX)",
                "version": "3.0.0",
                "decompiler": self.deci.name if self.deci else "unknown",
                "protocol": "unix_socket",
                "binary_hash": self.deci.binary_hash if self.deci else None
            }
        
        elif request_type == "get_light_artifacts":
            collection_name = request.get("collection_name")
            return self._get_light_artifacts(collection_name)
        
        elif request_type == "get_full_artifact":
            collection_name = request.get("collection_name")
            key = request.get("key")
            collection = getattr(self.deci, collection_name)
            artifact = collection[key]
            
            # Serialize the full artifact safely
            if hasattr(artifact, 'dumps') and hasattr(artifact, '__class__'):
                try:
                    return {
                        'type': artifact.__class__.__name__,
                        'module': artifact.__class__.__module__,
                        'data': artifact.dumps(),
                        'is_artifact': True
                    }
                except Exception as e:
                    _l.warning(f"Failed to serialize full artifact: {e}")
                    # Fall back to direct return, which might fail with pickle
                    return artifact
            else:
                return artifact
        
        elif request_type == "method_call":
            method_name = request.get("method_name")
            args = request.get("args", [])
            kwargs = request.get("kwargs", {})
            
            # Handle dotted method names like "art_lifter.lift"
            if "." in method_name:
                obj = self.deci
                for attr in method_name.split("."):
                    obj = getattr(obj, attr)
                method = obj
            else:
                # Get the method from the decompiler interface
                method = getattr(self.deci, method_name)
            result = method(*args, **kwargs)
            
            # Check if result is an artifact and serialize it properly
            if hasattr(result, 'dumps') and hasattr(result, '__class__'):
                # This looks like an artifact, serialize it safely
                try:
                    return {
                        'type': result.__class__.__name__,
                        'module': result.__class__.__module__,
                        'data': result.dumps(),
                        'is_artifact': True
                    }
                except Exception as e:
                    _l.warning(f"Failed to serialize result artifact: {e}")
                    # Fall back to direct return, which might fail with pickle
                    return result
            else:
                # Not an artifact, return as-is
                return result
        
        elif request_type == "property_get":
            property_name = request.get("property_name")
            return getattr(self.deci, property_name)
        
        elif request_type == "shutdown_deci":
            if self.deci:
                self.deci.shutdown()
            return {"status": "shutdown"}
        
        else:
            raise ValueError(f"Unknown request type: {request_type}")
    
    def _get_light_artifacts(self, collection_name: str) -> Dict:
        """Get light artifacts for a collection, computing and caching on first request"""
        with self._cache_lock:
            cache_entry = self._light_caches.get(collection_name)
            
            # Check if we have a valid cache entry
            if cache_entry and time.time() - cache_entry["timestamp"] < self._cache_ttl:
                return cache_entry["items"]
            
            # Cache miss or stale - compute light artifacts on-demand
            _l.debug(f"Computing light artifacts for {collection_name} on-demand")
            try:
                collection = getattr(self.deci, collection_name)
                if hasattr(collection, '_lifted_art_lister'):
                    start_time = time.time()
                    light_items = collection._lifted_art_lister()
                    end_time = time.time()
                    
                    # Convert artifacts to serializable format using their own serialization
                    serializable_items = {}
                    for addr, artifact in light_items.items():
                        try:
                            # Use the artifact's built-in serialization which handles complex objects
                            serialized = artifact.dumps()
                            # Store as a tuple of (type_name, serialized_data) for reconstruction
                            serializable_items[addr] = {
                                'type': artifact.__class__.__name__,
                                'module': artifact.__class__.__module__,
                                'data': serialized
                            }
                        except Exception as e:
                            _l.warning(f"Failed to serialize {artifact.__class__.__name__} at 0x{addr:x}: {e}")
                            # Skip problematic artifacts rather than failing completely
                            continue
                    
                    # Cache the serializable artifacts
                    self._light_caches[collection_name] = {
                        "items": serializable_items,
                        "timestamp": time.time()
                    }
                    
                    _l.info(f"Computed {len(serializable_items)} light {collection_name} in {end_time - start_time:.3f}s")
                    return serializable_items
                else:
                    _l.warning(f"Collection {collection_name} does not support light artifacts")
                    return {}
                    
            except Exception as e:
                _l.warning(f"Failed to compute light artifacts for {collection_name}: {e}")
                # Return stale cache if available, otherwise empty dict
                if cache_entry:
                    _l.debug(f"Returning stale cache for {collection_name} due to error")
                    return cache_entry["items"]
                return {}


class DecompilerServer:
    """
    A server that exposes DecompilerInterface APIs over AF_UNIX sockets.
    
    This server wraps a DecompilerInterface instance and provides network access
    to all its public methods and artifact collections through AF_UNIX sockets.
    """
    
    def __init__(self, 
                 decompiler_interface: Optional[DecompilerInterface] = None,
                 socket_path: Optional[str] = None,
                 **interface_kwargs):
        """
        Initialize the DecompilerServer.
        
        Args:
            decompiler_interface: An existing DecompilerInterface instance. If None,
                                one will be created using DecompilerInterface.discover()
            socket_path: Path for the AF_UNIX socket. If None, a temporary path will be used
            **interface_kwargs: Arguments passed to DecompilerInterface.discover() if
                              decompiler_interface is None
        """
        
        self.socket_path = socket_path
        self._server_socket = None
        self._server_thread = None
        self._running = False
        self._clients = []
        self._client_threads = []
        
        # Initialize the decompiler interface
        if decompiler_interface is not None:
            self.deci = decompiler_interface
        else:
            _l.info("Discovering decompiler interface...")
            self.deci = DecompilerInterface.discover(**interface_kwargs)
            if self.deci is None:
                raise RuntimeError("Failed to discover decompiler interface")
        
        # Create socket handler
        self.handler = SocketServerHandler(self.deci)
        
        # Generate socket path if not provided
        if self.socket_path is None:
            temp_dir = tempfile.mkdtemp(prefix="libbs_server_")
            self.socket_path = os.path.join(temp_dir, "decompiler.sock")
            self._temp_dir = temp_dir
        else:
            self._temp_dir = None
        
        _l.info(f"DecompilerServer initialized with {self.deci.name} interface")
        _l.info(f"Socket path: {self.socket_path}")
    
    def start(self):
        """Start the server in a separate thread"""
        if self._running:
            _l.warning("Server is already running")
            return
        
        _l.info(f"Starting DecompilerServer on {self.socket_path}")
        
        # Create AF_UNIX socket
        self._server_socket = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        
        # Remove socket file if it exists
        if os.path.exists(self.socket_path):
            os.unlink(self.socket_path)
        
        # Bind and listen
        self._server_socket.bind(self.socket_path)
        self._server_socket.listen(5)
        
        # Set running flag before starting thread
        self._running = True
        
        # Start server in a separate thread
        self._server_thread = threading.Thread(target=self._server_loop, daemon=True)
        self._server_thread.start()
        
        _l.info(f"DecompilerServer started successfully on unix://{self.socket_path}")
        _l.info("Connect with: DecompilerClient.discover('unix://{}')".format(self.socket_path))
    
    def _server_loop(self):
        """Main server loop"""
        try:
            while self._running:
                try:
                    client_socket, addr = self._server_socket.accept()
                    self._clients.append(client_socket)
                    
                    # Handle client in separate thread
                    client_thread = threading.Thread(
                        target=self.handler.handle_client,
                        args=(client_socket, str(addr)),
                        daemon=True
                    )
                    self._client_threads.append(client_thread)
                    client_thread.start()
                    
                except OSError:
                    # Socket was closed
                    break
                except Exception as e:
                    _l.error(f"Error accepting client: {e}")
                    
        except Exception as e:
            _l.error(f"Server loop error: {e}")
        finally:
            _l.info("Server loop ended")
    
    def stop(self):
        """Stop the server"""
        if not self._running:
            _l.warning("Server is not running")
            return
        
        _l.info("Stopping DecompilerServer...")
        self._running = False
        
        # Close all client connections
        for client in self._clients:
            try:
                client.close()
            except:
                pass
        
        # Close server socket
        if self._server_socket:
            self._server_socket.close()
        
        # Wait for threads to finish
        if self._server_thread and self._server_thread.is_alive():
            self._server_thread.join(timeout=5.0)
        
        for thread in self._client_threads:
            if thread.is_alive():
                thread.join(timeout=1.0)
        
        # Clean up socket file and temp directory
        if os.path.exists(self.socket_path):
            os.unlink(self.socket_path)
        
        if self._temp_dir and os.path.exists(self._temp_dir):
            try:
                os.rmdir(self._temp_dir)
            except:
                pass
        
        _l.info("DecompilerServer stopped")
    
    def is_running(self) -> bool:
        """Check if the server is currently running"""
        return self._running
    
    def wait_for_shutdown(self):
        """Wait for the server to be shut down (blocking)"""
        if self._server_thread and self._server_thread.is_alive():
            try:
                self._server_thread.join()
            except KeyboardInterrupt:
                _l.info("Received interrupt signal, stopping server...")
                self.stop()
    
    def __enter__(self):
        """Context manager entry"""
        self.start()
        return self
    
    def __exit__(self, exc_type, exc_val, exc_tb):
        """Context manager exit"""
        self.stop()
        if self.deci:
            self.deci.shutdown()