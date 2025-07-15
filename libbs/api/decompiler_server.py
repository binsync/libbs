import logging
import threading
import time
from typing import Optional, Dict, Any, List
import rpyc
from rpyc.utils.server import ThreadedServer
from pathlib import Path

from libbs.api.decompiler_interface import DecompilerInterface

_l = logging.getLogger(__name__)

# Global reference to the decompiler interface for the service
_global_deci = None
_global_light_caches = {}
_global_cache_lock = threading.Lock()
_global_cache_ttl = 10.0


class DecompilerService(rpyc.Service):
    """
    RPyC service that exposes DecompilerInterface APIs.
    
    This service wraps a DecompilerInterface instance and provides transparent
    remote access to all its methods and artifact collections.
    """
    
    def on_connect(self, conn):
        """Called when a client connects"""
        super().on_connect(conn)
        _l.info("Client connected")
    
    def on_disconnect(self, conn):
        """Called when a client disconnects"""
        super().on_disconnect(conn)
        _l.info("Client disconnected")
    
    # Expose the DecompilerInterface directly for transparent access
    def exposed_get_deci(self):
        """Get the underlying DecompilerInterface"""
        global _global_deci
        return _global_deci
    
    # Expose fast bulk operations for collections
    def exposed_get_light_artifacts(self, collection_name: str) -> Dict:
        """Get all light artifacts for a collection in a single call"""
        return _get_light_artifacts(collection_name)
    
    def exposed_get_artifact_keys(self, collection_name: str) -> List:
        """Get all keys for a collection"""
        light_items = _get_light_artifacts(collection_name)
        return list(light_items.keys())
    
    def exposed_get_full_artifact(self, collection_name: str, key):
        """Get a full artifact by key (bypasses light artifact cache)"""
        global _global_deci
        collection = getattr(_global_deci, collection_name)
        return collection[key]
    
    def exposed_server_info(self) -> Dict[str, Any]:
        """Get information about the server"""
        global _global_deci
        return {
            "name": "LibBS DecompilerServer (RPyC)",
            "version": "2.0.0",
            "decompiler": _global_deci.name if _global_deci else "unknown",
            "protocol": "rpyc"
        }
    
    def exposed_shutdown_deci(self):
        """Shutdown the underlying decompiler interface"""
        global _global_deci
        if _global_deci:
            _global_deci.shutdown()




def _get_light_artifacts(collection_name: str) -> Dict:
    """Get light artifacts for a collection, computing and caching on first request"""
    global _global_deci, _global_light_caches, _global_cache_lock, _global_cache_ttl
    
    with _global_cache_lock:
        cache_entry = _global_light_caches.get(collection_name)
        
        # Check if we have a valid cache entry
        if cache_entry and time.time() - cache_entry["timestamp"] < _global_cache_ttl:
            return cache_entry["items"]
        
        # Cache miss or stale - compute light artifacts on-demand
        _l.debug(f"Computing light artifacts for {collection_name} on-demand")
        try:
            collection = getattr(_global_deci, collection_name)
            if hasattr(collection, '_lifted_art_lister'):
                start_time = time.time()
                light_items = collection._lifted_art_lister()
                end_time = time.time()
                
                # Cache the computed artifacts
                _global_light_caches[collection_name] = {
                    "items": light_items,
                    "timestamp": time.time()
                }
                
                _l.info(f"Computed {len(light_items)} light {collection_name} in {end_time - start_time:.3f}s")
                return light_items
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
    A server that exposes DecompilerInterface APIs over RPyC.
    
    This server wraps a DecompilerInterface instance and provides network access
    to all its public methods and artifact collections through RPyC.
    """
    
    def __init__(self, 
                 decompiler_interface: Optional[DecompilerInterface] = None,
                 host: str = "localhost", 
                 port: int = 18861,  # Default RPyC registry port + 1
                 **interface_kwargs):
        """
        Initialize the DecompilerServer.
        
        Args:
            decompiler_interface: An existing DecompilerInterface instance. If None,
                                one will be created using DecompilerInterface.discover()
            host: Host address to bind the server to
            port: Port number to bind the server to  
            **interface_kwargs: Arguments passed to DecompilerInterface.discover() if
                              decompiler_interface is None
        """
        global _global_deci
        
        self.host = host
        self.port = port
        self._server = None
        self._server_thread = None
        self._running = False
        
        # Initialize the decompiler interface
        if decompiler_interface is not None:
            self.deci = decompiler_interface
        else:
            _l.info("Discovering decompiler interface...")
            self.deci = DecompilerInterface.discover(**interface_kwargs)
            if self.deci is None:
                raise RuntimeError("Failed to discover decompiler interface")
        
        # Set global reference for the service
        _global_deci = self.deci
        
        _l.info(f"DecompilerServer initialized with {self.deci.name} interface")
        _l.info("Light artifact caches will be computed on first request")
    
    def start(self):
        """Start the server in a separate thread"""
        if self._running:
            _l.warning("Server is already running")
            return
        
        _l.info(f"Starting DecompilerServer on {self.host}:{self.port}")
        
        # Create and configure RPyC server
        self._server = ThreadedServer(
            DecompilerService, 
            hostname=self.host, 
            port=self.port,
            protocol_config={
                'allow_public_attrs': True,
                'allow_pickle': True,
                'sync_request_timeout': 60.0,
                'allow_setattr': True,
                'allow_delattr': True,
            }
        )
        
        # Start server in a separate thread
        self._server_thread = threading.Thread(target=self._server.start, daemon=True)
        self._server_thread.start()
        self._running = True
        
        _l.info(f"DecompilerServer started successfully on rpyc://{self.host}:{self.port}")
        _l.info("RPyC transparent proxy available for DecompilerInterface")
        _l.info("Connect with: DecompilerClient.discover('rpyc://{}:{}')".format(self.host, self.port))
    
    def stop(self):
        """Stop the server"""
        if not self._running:
            _l.warning("Server is not running")
            return
        
        _l.info("Stopping DecompilerServer...")
        
        if self._server:
            self._server.close()
        
        if self._server_thread and self._server_thread.is_alive():
            self._server_thread.join(timeout=5.0)
        
        self._running = False
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