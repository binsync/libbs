import argparse
import sys
import logging
from pathlib import Path
import importlib
import importlib.resources

from libbs.plugin_installer import LibBSPluginInstaller

_l = logging.getLogger(__name__)


def install():
    LibBSPluginInstaller().install()


def start_server(host="localhost", port=18861, decompiler=None, binary_path=None, headless=False):
    """Start the DecompilerServer (RPyC-based)"""
    try:
        from libbs.api.decompiler_server import DecompilerServer
        from libbs.api.decompiler_interface import DecompilerInterface
        
        # Configure logging
        logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(name)s - %(levelname)s - %(message)s')
        
        # Prepare interface kwargs
        interface_kwargs = {}
        if decompiler:
            interface_kwargs['force_decompiler'] = decompiler
        if binary_path:
            interface_kwargs['binary_path'] = binary_path
        if headless:
            interface_kwargs['headless'] = headless
        
        # Create and start server
        _l.info(f"Starting RPyC DecompilerServer on {host}:{port}")
        if interface_kwargs:
            _l.info(f"Interface options: {interface_kwargs}")
        
        with DecompilerServer(host=host, port=port, **interface_kwargs) as server:
            _l.info("Server started successfully. Press Ctrl+C to stop.")
            _l.info("Connect with: DecompilerClient.discover('rpyc://{}:{}')".format(host, port))
            try:
                server.wait_for_shutdown()
            except KeyboardInterrupt:
                _l.info("Shutting down server...")
                
    except ImportError as e:
        _l.error(f"Failed to import required modules: {e}")
        _l.error("Make sure RPyC is installed: pip install rpyc")
        sys.exit(1)
    except Exception as e:
        _l.error(f"Failed to start server: {e}")
        sys.exit(1)


def test_client(server_url="rpyc://localhost:18861"):
    """Test the DecompilerClient connection"""
    try:
        from libbs.api.decompiler_client import DecompilerClient
        
        # Configure logging
        logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(name)s - %(levelname)s - %(message)s')
        
        _l.info(f"Testing connection to RPyC DecompilerServer at {server_url}")
        
        with DecompilerClient.discover(server_url=server_url) as client:
            _l.info(f"Successfully connected to {client.name} decompiler")
            _l.info(f"Binary path: {client.binary_path}")
            _l.info(f"Binary hash: {client.binary_hash}")
            _l.info(f"Decompiler available: {client.decompiler_available}")
            
            # Test fast artifact collections (benchmark performance)
            import time
            start_time = time.time()
            functions = list(client.functions.items())
            end_time = time.time()
            _l.info(f"Retrieved {len(functions)} functions in {end_time - start_time:.3f}s")
            
            start_time = time.time()
            comments = list(client.comments.keys())
            end_time = time.time()
            _l.info(f"Retrieved {len(comments)} comment keys in {end_time - start_time:.3f}s")
            
            _l.info("✅ Client test completed successfully!")
            
    except ImportError as e:
        _l.error(f"Failed to import required modules: {e}")
        _l.error("Make sure RPyC is installed: pip install rpyc")
        sys.exit(1)
    except Exception as e:
        _l.error(f"Client test failed: {e}")
        sys.exit(1)


def main():
    parser = argparse.ArgumentParser(
            description="""
            The LibBS Command Line Util. This is the script interface to LibBS that allows you to install and run 
            the Ghidra UI for running plugins, and start the DecompilerServer. 
            """,
            epilog="""
            Examples:
            libbs --install
            libbs --server --host 0.0.0.0 --port 18861
            libbs --server --decompiler ghidra --binary-path /path/to/binary --headless
            libbs --client --server-url rpyc://remote-server:18861
            """
    )
    parser.add_argument(
        "--install", action="store_true", help="""
        Install all the LibBS plugins to every decompiler. 
        """
    )
    parser.add_argument(
        "--single-decompiler-install", nargs=2, metavar=('decompiler', 'path'), help="Install DAILA into a single decompiler. Decompiler must be one of: ida, ghidra, binja, angr."
    )
    parser.add_argument(
        "--server", action="store_true", help="""
        Start the DecompilerServer to expose DecompilerInterface APIs over RPyC.
        """
    )
    parser.add_argument(
        "--client", action="store_true", help="""
        Test the DecompilerClient connection to a running DecompilerServer.
        """
    )
    parser.add_argument(
        "--server-url", default="rpyc://localhost:18861", help="""
        URL of the DecompilerServer to connect to (default: rpyc://localhost:18861).
        """
    )
    parser.add_argument(
        "--host", default="localhost", help="""
        Host address for the DecompilerServer (default: localhost). Use 0.0.0.0 to bind to all interfaces.
        """
    )
    parser.add_argument(
        "--port", type=int, default=18861, help="""
        Port number for the DecompilerServer (default: 18861).
        """
    )
    parser.add_argument(
        "--decompiler", choices=["ida", "ghidra", "binja", "angr"], help="""
        Force a specific decompiler for the server. If not specified, auto-detection will be used.
        """
    )
    parser.add_argument(
        "--binary-path", help="""
        Path to the binary file to analyze (required for headless mode).
        """
    )
    parser.add_argument(
        "--headless", action="store_true", help="""
        Run the decompiler in headless mode (no GUI). Requires --binary-path.
        """
    )
    args = parser.parse_args()

    if args.single_decompiler_install:
        decompiler, path = args.single_decompiler_install
        LibBSPluginInstaller().install(interactive=False, paths_by_target={decompiler: path})
    elif args.install:
        install()
    elif args.server:
        if args.headless and not args.binary_path:
            parser.error("--headless requires --binary-path")
        start_server(
            host=args.host,
            port=args.port,
            decompiler=args.decompiler,
            binary_path=args.binary_path,
            headless=args.headless
        )
    elif args.client:
        test_client(server_url=args.server_url)
    else:
        parser.print_help()


if __name__ == "__main__":
    main()
