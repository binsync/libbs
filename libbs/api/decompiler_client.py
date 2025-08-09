import logging
import threading
import time
from typing import Dict, Any, Optional, List, Union, Callable
import rpyc

from libbs.artifacts import (
    Artifact, Function, Comment, Patch, GlobalVariable, 
    Struct, Enum, Typedef, Context, Decompilation
)

_l = logging.getLogger(__name__)


class FastClientArtifactDict(dict):
    """
    A fast client-side proxy for ArtifactDict that communicates with DecompilerServer via RPyC.
    
    This class mimics the behavior of ArtifactDict but uses RPyC for bulk operations
    and maintains the same performance characteristics as the local version by using
    the _lifted_art_lister pattern.
    """
    
    def __init__(self, collection_name: str, artifact_class, client: 'DecompilerClient'):
        super().__init__()
        self.collection_name = collection_name
        self.artifact_class = artifact_class
        self.client = client
        self._light_cache = {}
        self._light_cache_timestamp = 0
        self._cache_ttl = 10.0  # Cache for 10 seconds
    
    def _get_light_artifacts(self) -> Dict:
        """Get all light artifacts using the server's fast bulk operation"""
        current_time = time.time()
        if current_time - self._light_cache_timestamp > self._cache_ttl:
            # Cache expired, fetch from server using bulk endpoint
            try:
                _l.debug(f"Fetching light artifacts for {self.collection_name}")
                self._light_cache = self.client._service.get_light_artifacts(self.collection_name)
                self._light_cache_timestamp = current_time
            except Exception as e:
                _l.warning(f"Failed to fetch light artifacts for {self.collection_name}: {e}")
                
        return self._light_cache
    
    def _invalidate_cache(self):
        """Invalidate the light artifact cache"""
        self._light_cache.clear()
        self._light_cache_timestamp = 0
    
    def __len__(self):
        """Return the number of items in the collection"""
        light_items = self._get_light_artifacts()
        return len(light_items)
    
    def __iter__(self):
        """Iterate over keys in the collection"""
        light_items = self._get_light_artifacts()
        return iter(light_items.keys())
    
    def keys(self):
        """Return an iterator over the keys (fast bulk operation)"""
        light_items = self._get_light_artifacts()
        return light_items.keys()
    
    def values(self):
        """Return an iterator over the values (light artifacts, fast bulk operation)"""
        light_items = self._get_light_artifacts()
        return light_items.values()
    
    def items(self):
        """Return an iterator over (key, value) pairs (fast bulk operation)"""
        light_items = self._get_light_artifacts()
        return light_items.items()
    
    def __getitem__(self, key):
        """Get a full artifact by key (same behavior as local ArtifactDict)"""
        # First, check if the key exists by looking at light artifacts
        light_items = self._get_light_artifacts()
        if key not in light_items:
            raise KeyError(f"Key {key} not found in {self.collection_name}")
        
        # Key exists, get the full artifact from server
        try:
            return self.client._service.get_full_artifact(self.collection_name, key)
        except Exception as e:
            if "not found" in str(e).lower():
                raise KeyError(f"Key {key} not found in {self.collection_name}")
            else:
                raise
    
    def get_light(self, key):
        """Get a light artifact by key (fast, cached access)"""
        light_items = self._get_light_artifacts()
        if key not in light_items:
            raise KeyError(f"Key {key} not found in {self.collection_name}")
        return light_items[key]
    
    def get_full(self, key):
        """Explicitly get a full artifact (with expensive operations like decompilation)"""
        try:
            return self.client._service.get_full_artifact(self.collection_name, key)
        except Exception as e:
            if "not found" in str(e).lower():
                raise KeyError(f"Key {key} not found in {self.collection_name}")
            else:
                raise
    
    def __setitem__(self, key, value):
        """Set an artifact by key on the server"""
        if not isinstance(value, self.artifact_class):
            raise ValueError(f"Expected {self.artifact_class.__name__}, got {type(value).__name__}")
        
        # Use the direct decompiler interface for setting artifacts
        success = self.client._deci.set_artifact(value)
        
        # Invalidate cache since we modified the collection
        self._invalidate_cache()
        
        if not success:
            raise RuntimeError(f"Failed to set artifact")
    
    def __delitem__(self, key):
        """Delete an artifact by key (not implemented in decompiler interfaces)"""
        raise NotImplementedError("Deletion not supported by DecompilerInterface")
    
    def __contains__(self, key):
        """Check if a key exists in the collection"""
        light_items = self._get_light_artifacts()
        return key in light_items
    
    def get(self, key, default=None):
        """Get a full artifact with a default value"""
        try:
            return self[key]  # Use __getitem__ which returns full artifact
        except KeyError:
            return default


class DecompilerClient:
    """
    A client that connects to DecompilerServer via RPyC and provides the same interface as DecompilerInterface.
    
    This class acts as a transparent proxy to a remote DecompilerInterface, allowing users to
    write code that works identically whether using a local or remote decompiler.
    """
    
    def __init__(self, 
                 host: str = "localhost", 
                 port: int = 18861,
                 timeout: float = 30.0):
        """
        Initialize the DecompilerClient.
        
        Args:
            host: Server hostname or IP address
            port: Server port number
            timeout: Connection timeout in seconds
        """
        self.host = host
        self.port = port
        self.timeout = timeout
        
        # Connection state
        self._conn = None
        self._service = None
        self._deci = None
        self._connected = False
        self._server_info = None
        
        # Try to connect
        self._connect()
        
        # Initialize fast artifact collections
        self.functions = FastClientArtifactDict("functions", Function, self)
        self.comments = FastClientArtifactDict("comments", Comment, self)
        self.patches = FastClientArtifactDict("patches", Patch, self)
        self.global_vars = FastClientArtifactDict("global_vars", GlobalVariable, self)
        self.structs = FastClientArtifactDict("structs", Struct, self)
        self.enums = FastClientArtifactDict("enums", Enum, self)
        self.typedefs = FastClientArtifactDict("typedefs", Typedef, self)
        
        _l.info(f"DecompilerClient connected to {host}:{port}")
    
    def _connect(self):
        """Establish connection to the server"""
        try:
            _l.debug(f"Attempting to connect to RPyC server at {self.host}:{self.port}")
            self._conn = rpyc.connect(
                self.host, 
                self.port,
                config={
                    'allow_public_attrs': True,
                    'allow_pickle': True,
                    'sync_request_timeout': self.timeout,
                    'allow_setattr': True,
                    'allow_delattr': True,
                }
            )
            _l.debug("RPyC connection established")
            
            self._service = self._conn.root
            _l.debug("Got service root")
            
            # Test the connection by getting server info first
            self._server_info = self._service.server_info()
            _l.debug(f"Got server info: {self._server_info}")
            
            # Now get the decompiler interface
            self._deci = self._service.get_deci()
            _l.debug("Got decompiler interface")
            
            self._connected = True
            
            _l.info(f"Connected to {self._server_info.get('name', 'DecompilerServer')} "
                   f"using {self._server_info.get('decompiler', 'unknown')} decompiler")
        except Exception as e:
            import traceback
            _l.error(f"Failed to connect to DecompilerServer at {self.host}:{self.port}: {e}")
            _l.debug(f"Full traceback: {traceback.format_exc()}")
            
            # Provide helpful error messages for common issues
            if "Connection refused" in str(e):
                raise ConnectionError(f"Cannot connect to DecompilerServer at {self.host}:{self.port}. "
                                    f"Make sure the server is running with: libbs --server")
            elif "not enough values to unpack" in str(e):
                raise ConnectionError(f"RPyC protocol error. Make sure both client and server are using "
                                    f"the same LibBS version with RPyC support.")
            else:
                raise ConnectionError(f"Cannot connect to DecompilerServer: {e}")
    
    # Properties - mirror DecompilerInterface properties
    @property
    def name(self) -> str:
        """Name of the decompiler"""
        return self._server_info.get('decompiler', 'remote')
    
    @property
    def binary_base_addr(self) -> int:
        """Base address of the binary"""
        return self._deci.binary_base_addr
    
    @property
    def binary_hash(self) -> str:
        """Hash of the binary"""
        return self._deci.binary_hash
    
    @property
    def binary_path(self) -> Optional[str]:
        """Path to the binary"""
        return self._deci.binary_path
    
    @property
    def decompiler_available(self) -> bool:
        """Whether decompiler is available"""
        return self._deci.decompiler_available
    
    @property
    def default_pointer_size(self) -> int:
        """Default pointer size"""
        return self._deci.default_pointer_size
    
    # GUI API methods - delegate to remote decompiler
    def gui_active_context(self) -> Optional[Context]:
        """Get the active context from the GUI"""
        return self._deci.gui_active_context()
    
    def gui_goto(self, func_addr) -> None:
        """Go to an address in the GUI"""
        return self._deci.gui_goto(func_addr)
    
    def gui_show_type(self, type_name: str) -> None:
        """Show a type in the GUI"""
        return self._deci.gui_show_type(type_name)
    
    def gui_ask_for_string(self, question: str, title: str = "Plugin Question") -> str:
        """Ask for a string input"""
        return self._deci.gui_ask_for_string(question, title)
    
    def gui_ask_for_choice(self, question: str, choices: list, title: str = "Plugin Question") -> str:
        """Ask for a choice from a list"""
        return self._deci.gui_ask_for_choice(question, choices, title)
    
    def gui_popup_text(self, text: str, title: str = "Plugin Message") -> bool:
        """Show a popup message"""
        return self._deci.gui_popup_text(text, title)
    
    # Core decompiler API methods - delegate to remote decompiler
    def fast_get_function(self, func_addr) -> Optional[Function]:
        """Get a light version of a function"""
        return self._deci.fast_get_function(func_addr)
    
    def get_func_size(self, func_addr) -> int:
        """Get the size of a function"""
        return self._deci.get_func_size(func_addr)
    
    def decompile(self, addr: int, map_lines=False, **kwargs) -> Optional[Decompilation]:
        """Decompile a function"""
        return self._deci.decompile(addr, map_lines=map_lines, **kwargs)
    
    def xrefs_to(self, artifact: Artifact, decompile=False, only_code=False) -> List[Artifact]:
        """Get cross-references to an artifact"""
        return self._deci.xrefs_to(artifact, decompile=decompile, only_code=only_code)
    
    def get_callgraph(self, only_names=False):
        """Get the call graph"""
        return self._deci.get_callgraph(only_names=only_names)
    
    def get_dependencies(self, artifact: Artifact, decompile=True, max_resolves=50, **kwargs) -> List[Artifact]:
        """Get dependencies for an artifact"""
        return self._deci.get_dependencies(artifact, decompile=decompile, 
                                          max_resolves=max_resolves, **kwargs)
    
    def get_func_containing(self, addr: int) -> Optional[Function]:
        """Get the function containing an address"""
        return self._deci.get_func_containing(addr)
    
    def get_decompilation_object(self, function: Function, **kwargs):
        """Get the decompilation object for a function"""
        return self._deci.get_decompilation_object(function, **kwargs)
    
    def set_artifact(self, artifact: Artifact, lower=True, **kwargs) -> bool:
        """Set an artifact in the decompiler"""
        return self._deci.set_artifact(artifact, lower=lower, **kwargs)
    
    def get_defined_type(self, type_str: str):
        """Get a defined type by string"""
        return self._deci.get_defined_type(type_str)
    
    # Optional API methods - delegate to remote decompiler
    def undo(self) -> None:
        """Undo the last operation"""
        return self._deci.undo()
    
    def local_variable_names(self, func: Function) -> List[str]:
        """Get local variable names for a function"""
        return self._deci.local_variable_names(func)
    
    def rename_local_variables_by_names(self, func: Function, name_map: Dict[str, str], **kwargs) -> bool:
        """Rename local variables by name map"""
        return self._deci.rename_local_variables_by_names(func, name_map, **kwargs)
    
    # Logging methods - delegate to remote decompiler
    def print(self, msg: str, **kwargs) -> None:
        """Print a message"""
        return self._deci.print(msg, **kwargs)
    
    def info(self, msg: str, **kwargs) -> None:
        """Log an info message"""
        return self._deci.info(msg, **kwargs)
    
    def debug(self, msg: str, **kwargs) -> None:
        """Log a debug message"""
        return self._deci.debug(msg, **kwargs)
    
    def warning(self, msg: str, **kwargs) -> None:
        """Log a warning message"""
        return self._deci.warning(msg, **kwargs)
    
    def error(self, msg: str, **kwargs) -> None:
        """Log an error message"""
        return self._deci.error(msg, **kwargs)
    
    # Lifecycle methods
    def shutdown(self) -> None:
        """Shutdown the client"""
        _l.info("DecompilerClient shutting down")
        if self._conn:
            self._conn.close()
        self._connected = False
    
    def is_connected(self) -> bool:
        """Check if connected to the server"""
        return self._connected and self._conn and not self._conn.closed
    
    def reconnect(self) -> None:
        """Reconnect to the server"""
        if self._conn:
            self._conn.close()
        self._connect()
    
    def ping(self) -> bool:
        """Ping the server to check connectivity"""
        try:
            self._service.server_info()
            return True
        except Exception:
            return False
    
    # Context manager support
    def __enter__(self):
        return self
    
    def __exit__(self, exc_type, exc_val, exc_tb):
        self.shutdown()
    
    # Static methods for compatibility
    @staticmethod
    def discover(server_url: str = None, **kwargs) -> 'DecompilerClient':
        """
        Discover and connect to a DecompilerServer.
        
        This method provides a similar interface to DecompilerInterface.discover()
        but connects to a remote server instead.
        
        Args:
            server_url: URL of the server (e.g., "rpyc://localhost:18861")
            **kwargs: Additional arguments for DecompilerClient constructor
        
        Returns:
            Connected DecompilerClient instance
        """
        if server_url:
            # Parse server URL
            if "://" in server_url:
                protocol, rest = server_url.split("://", 1)
                if protocol != "rpyc":
                    _l.warning(f"Expected rpyc:// protocol, got {protocol}://")
                if ":" in rest:
                    host, port = rest.split(":", 1)
                    port = int(port.rstrip("/"))
                else:
                    host = rest.rstrip("/")
                    port = 18861  # Default RPyC port
            else:
                # Assume it's host:port format
                if ":" in server_url:
                    host, port = server_url.split(":", 1)
                    port = int(port)
                else:
                    host = server_url
                    port = 18861
            
            return DecompilerClient(host=host, port=port, **kwargs)
        else:
            # Use default localhost:18861
            return DecompilerClient(**kwargs)