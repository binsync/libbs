# LibBS
The decompiler API that works everywhere!

LibBS is an abstracted decompiler API that enables you to write plugins/scripts that work, with minimal edit, 
in every decompiler supported by LibBS. LibBS was originally designed to work with [BinSync](https://binsync.net).

## Install
```bash
pip install -e .
```

## Usage
LibBS exposes all decompiler API through the abstract class `DecompilerInterface`. The `DecompilerInterface` 
can be used in either the default mode, which assumes a GUI, or `headless` mode. In `headless` mode, the interface will 
start a new process using a specified decompiler. 

### UI Mode (default)
To use the same script everywhere, use the convenience function `DecompilerInterface.discover_interface()`, which will
auto find the correct interface. Copy the below code into any supported decompiler and it should run without edit.
```python
from libbs.api import DecompilerInterface
deci = DecompilerInterface.discover_interface()
for function in deci.functions:
    if function.header.type == "void *":
        function.header.type = "long long"
    
    deci.functions[function.addr] = function
```

### Headless Mode 
To use headless mode you must specify a decompiler to use. You can get the traditional interface using the following:
```python 
from libbs.api import DecompilerInterface
deci = DecompilerInterface.discover_interface(force_decompiler="ida", headless=True)
```

### Artifact Access Caveats
In designing the dictionaries that contain all Artifacts in a decompiler, we had a clash between ease-of-use and speed. 
When accessing some artifacts like a `Function`, we must decompile the function. Decompiling is slow. Due to this issue
we slightly changed how these dictionaries work to fast accessing. 

The only way to access a **full** artifact is to use the `getitem` interface of a dictionary. In practice this 
looks like the following:
```python
for func_addr, light_func in deci.functions.items():
    full_function = deci.function[func_addr]
```

Notice, when using the `items` function the function is `light`, meaning it does not contain stack vars and other 
info. This also means using `keys`, `values`, or `list` on an artifact dictionary will have the same affect. 

## TODO
G/S: Getters/Setters
- [ ] Add all decompilers to auto-detect interface

### ALL
- [ ] Move hook-inits to inside the `Interface` creation for all decompilers?
  - This could cause issues. What happens when this is done twice?

### IDA
- [ ] Change Callbacks
- [ ] G/S Comments

### Binja
- [ ] Change Callbacks

### Ghidra
- [ ] Change Callbacks
- [ ] Get/Set Comments

### angr
- [ ] Change Callbacks

