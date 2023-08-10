# YODALib
 Your Only Decompiler API Library (YODALib)! 

YODALib is an abstracted decompiler API that enables you to write plugins/scripts that work, with minimal edit, 
in every decompiler supported by YODALib. 

## Install
```bash
pip install -e .
```

## Usage
YODALib exposes all decompiler API through the abstract class `DecompilerInterface`. The `DecompilerInterface` 
can be used in either the default mode, which assumes a GUI, or `headless` mode. In `headless` mode, the interface will 
start a new process using a specified decompiler. 

### UI Mode (default)
To use the same script everywhere, use the convenience function `DecompilerInterface.discover_interface()`, which will
auto find the correct interface. Copy the below code into any supported decompiler and it should run without edit.
```python
from yodalib.api import DecompilerInterface
dec = DecompilerInterface.discover_interface()
for function in dec.functions:
    if function.header.type == "void *":
        function.header.type = "long long"
    
    dec.functions[function.addr] = function
```

### Headless Mode 
To use headless mode you must specify a decompiler to use. You can get the traditional interface using the following:
```python 
from yodalib.api import DecompilerInterface
dec = DecompilerInterface.discover_interface(force_decompiler="ida", headless=True)
```

## TODO
G/S: Getters/Setters
- [ ] Add all decompilers to auto-detect interface

### IDA
- [ ] Change Callbacks
- [ ] G/S Comments
- [ ] G/S Function Headers (args and type)

### Binja
- [ ] Every G/S
- [ ] Change Callbacks

### Ghidra
- [ ] Generic Interface Outline & Stubs
- [ ] Every G/S
- [ ] Change Callbacks

### angr
- [ ] Generic Interface Outline & Stubs
- [ ] Every G/S
- [ ] Change Callbacks

