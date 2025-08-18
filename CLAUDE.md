# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Overview

LibBS is a unified decompiler API that provides an abstracted interface for working with multiple decompilers (IDA Pro, Binary Ninja, Ghidra, angr-management). It enables writing plugins and scripts that work across all supported decompilers with minimal changes.

## Development Commands

### Installation and Setup
```bash
# Install libbs in development mode
pip install -e .

# Install libbs plugins to decompilers (required after pip install)
libbs --install

# Install to specific decompiler
libbs --single-decompiler-install ida /path/to/ida
```

### Testing
```bash
# Run tests with pytest
pytest tests/

# Run specific test files
pytest tests/test_artifacts.py
pytest tests/test_decompilers.py
pytest tests/test_cli.py
pytest tests/test_remote_ghidra.py
```

### Project Management
```bash
# Build the package
python -m build

# Install test dependencies
pip install -e ".[test]"

# Install ghidra dependencies  
pip install -e ".[ghidra]"
```

## Architecture

### Core Components

**DecompilerInterface** (`libbs/api/decompiler_interface.py`): The main abstraction layer that provides unified access to different decompilers. Can operate in GUI mode (default) or headless mode.

**ArtifactLifter** (`libbs/api/artifact_lifter.py`): Handles conversion between decompiler-specific objects and LibBS artifacts.

**Artifacts** (`libbs/artifacts/`): Unified data structures representing decompiler concepts:
- `Function`, `FunctionHeader`, `FunctionArgument`
- `StackVariable`, `GlobalVariable` 
- `Struct`, `StructMember`, `Enum`, `Typedef`
- `Comment`, `Patch`, `Context`, `Decompilation`

**Decompiler Implementations** (`libbs/decompilers/`):
- `ida/`: IDA Pro integration
- `binja/`: Binary Ninja integration  
- `ghidra/`: Ghidra integration (with bridge support)
- `angr/`: angr-management integration

### Plugin System

**Decompiler Stubs** (`libbs/decompiler_stubs/`): Plugin entry points for each decompiler that bootstrap LibBS functionality.

**Plugin Installer** (`libbs/plugin_installer.py`): Automatically installs LibBS plugins to detected decompiler installations.

### Key Design Patterns

**Artifact Dictionary Access**: Artifacts use a lazy-loading pattern where `.items()`, `.keys()`, `.values()` return "light" objects, but `dict[key]` returns full objects (which may trigger decompilation).

**Decompiler Discovery**: Use `DecompilerInterface.discover()` to auto-detect the current decompiler environment.

**Serialization**: All artifacts support JSON/TOML serialization via `.dumps()` and `.loads()` methods.

## Development Guidelines

### Adding New Decompiler Support
1. Create new directory in `libbs/decompilers/`
2. Implement `interface.py` inheriting from `DecompilerInterface`
3. Implement `artifact_lifter.py` inheriting from `ArtifactLifter` 
4. Add decompiler stub in `libbs/decompiler_stubs/`
5. Update `SUPPORTED_DECOMPILERS` constant

### Working with Artifacts
- Always use `deci.functions[addr]` to get full Function objects
- Use `for addr, light_func in deci.functions.items()` for iteration
- Test serialization with both JSON and TOML formats
- Validate artifacts work across all supported decompilers

### Testing Strategy
- Unit tests for artifacts (`test_artifacts.py`)
- Integration tests for decompiler interfaces (`test_decompilers.py`) 
- CLI testing (`test_cli.py`)
- Remote Ghidra functionality (`test_remote_ghidra.py`)

### Environment Variables
- `GHIDRA_HEADLESS_PATH`: Path to Ghidra headless binary for headless mode