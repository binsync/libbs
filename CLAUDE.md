# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Project Overview

LibBS is a universal decompiler API that provides a unified interface for working with multiple decompilers (IDA Pro, Binary Ninja, angr-management, and Ghidra). It's designed to enable writing plugins/scripts that work across all supported decompilers with minimal changes.

## Core Architecture

### Key Components

- **DecompilerInterface**: The main abstraction class that provides a unified API across all decompilers
- **Artifacts**: Core data structures representing decompiler objects (Function, Comment, Struct, etc.)
- **Decompiler-specific implementations**: Located in `libbs/decompilers/` with subdirectories for each supported decompiler
- **Plugin system**: Enables installation of LibBS plugins into target decompilers

### Important Directory Structure

- `libbs/api/`: Core API classes including `DecompilerInterface`, `ArtifactLifter`, and `ArtifactDict`
- `libbs/artifacts/`: All artifact types (Function, Comment, Struct, etc.)
- `libbs/decompilers/`: Decompiler-specific implementations for IDA, Ghidra, Binary Ninja, and angr
- `libbs/decompiler_stubs/`: Plugin files that get installed into target decompilers
- `examples/`: Example scripts and plugins demonstrating LibBS usage

### Artifact System

LibBS uses a special dictionary system for artifacts to balance ease-of-use with performance:
- Light access via `items()`, `keys()`, `values()` returns basic info without expensive operations
- Full access via `getitem` (e.g., `deci.functions[addr]`) triggers full decompilation/analysis

## Development Commands

### Testing
```bash
# Run core tests (artifacts and CLI)
pytest ./tests/test_artifacts.py ./tests/test_cli.py

# Run all tests
pytest tests/

# Run specific decompiler tests
pytest tests/test_decompilers.py
```

### Installation
```bash
# Install LibBS and its dependencies
pip install -e .

# Install LibBS plugins to all decompilers
libbs --install

# Install to specific decompiler
libbs --single-decompiler-install <decompiler> <path>
```

### DecompilerServer
```bash
# Start server with auto-detected decompiler (GUI mode)
libbs --server

# Start server on specific host/port
libbs --server --host 0.0.0.0 --port 8080

# Start server in headless mode with specific decompiler
libbs --server --decompiler ghidra --binary-path /path/to/binary --headless

# Server provides HTTP/JSON API endpoints:
# GET  /                     - Server info
# GET  /api                  - API overview  
# GET  /api/properties       - Decompiler properties
# GET  /api/functions        - Function collection
# POST /api/call             - Method calls
```

### DecompilerClient
```bash
# Test client connection to server
libbs --client --server-url http://localhost:8080

# Connect to remote server
libbs --client --server-url http://remote-host:8080
```

```python
# Use client in code (identical API to DecompilerInterface)
from libbs.api.decompiler_client import DecompilerClient

# Connect to remote server
with DecompilerClient.discover("http://localhost:8080") as deci:
    print(f"Functions: {len(deci.functions)}")
    func = deci.functions[0x401000]  # Same API as local interface
    
# Smart discovery (tries remote, falls back to local)
from libbs.api import DecompilerInterface
try:
    deci = DecompilerClient.discover("http://server:8080")
except:
    deci = DecompilerInterface.discover()  # Fallback to local
```

### Project Structure
- Python 3.10+ required
- Uses setuptools with pyproject.toml configuration
- Entry point: `libbs` command via `libbs.__main__:main`

## Key Patterns

### Interface Discovery
Use `DecompilerInterface.discover()` to auto-detect the current decompiler environment. This is the primary way to get a decompiler interface.

### DecompilerServer Architecture
The `DecompilerServer` wraps a `DecompilerInterface` and exposes all its public APIs over HTTP:
- **REST endpoints** for artifact collections (`/api/functions`, `/api/comments`, etc.)
- **JSON-RPC style calls** for method invocation (`/api/call`)
- **Property access** for decompiler metadata (`/api/properties`)
- Supports both GUI and headless decompiler modes
- Thread-safe request handling with automatic artifact serialization

### DecompilerClient Architecture
The `DecompilerClient` provides identical API to `DecompilerInterface` but connects to remote `DecompilerServer`:
- **Transparent proxy** - same code works with local or remote decompilers
- **High-performance bulk operations** - `items()` uses single request instead of N+1 
- **Light vs full artifacts** - fast light artifacts for collections, full artifacts on demand
- **Intelligent caching** - bulk light artifacts cached to minimize network requests
- **Automatic serialization** - artifacts serialized/deserialized transparently
- **Error handling** - network errors mapped to appropriate exceptions
- **Smart discovery** - can fall back from remote to local decompilers

### Performance Optimizations
- **Bulk endpoints**: `GET /api/functions?bulk=true&light=true` returns all light artifacts in one request
- **Light artifacts**: Fast collection operations (items(), values()) without expensive decompilation
- **Full artifacts**: `client.functions.get_full(addr)` for expensive operations when needed
- **Caching**: 10-second cache for bulk operations, 0ms access for cached artifacts
- **Result**: 76% performance improvement (30s → 7s for 29 function items())

### Headless Mode
For scripting outside decompilers, use `DecompilerInterface.discover(force_decompiler="ghidra", headless=True)`. Ghidra headless requires `GHIDRA_HEADLESS_PATH` environment variable.

### Artifact Serialization
All artifacts support TOML and JSON serialization via `.dumps()` and `.loads()` methods.

## Decompiler Support

- **IDA Pro**: >= 8.4 (use v1.26.0 for older versions)
- **Binary Ninja**: >= 2.4
- **angr-management**: >= 9.0
- **Ghidra**: >= 11.2

## Plugin Development

Plugins are installed via the `libbs --install` command which copies files from `libbs/decompiler_stubs/` to the appropriate decompiler directories. Each decompiler has its own plugin format and requirements.