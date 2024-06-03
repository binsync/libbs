# LibBS
The decompiler API that works everywhere!

LibBS is an abstracted decompiler API that enables you to write plugins/scripts that work, with minimal edit, 
in every decompiler supported by LibBS. LibBS was originally designed to work with [BinSync](https://binsync.net), and is the backbone
for all BinSync based plugins.

## Install
```bash
pip install libbs
```

The minimum Python version is **3.8**. **If you plan on using libbs alone (without installing some other plugin), 
you must do `libbs --install` after pip install**. This will copy the appropriate files to your decompiler. 

## Usage
LibBS exposes all decompiler API through the abstract class `DecompilerInterface`. The `DecompilerInterface` 
can be used in either the default mode, which assumes a GUI, or `headless` mode. In `headless` mode, the interface will 
start a new process using a specified decompiler.

You can find various examples using LibBS in the [examples](./examples) folder. Examples that are plugins show off
more of the complicated API that allows you to use an abstracted UI, artifacts, and more. 

### UI Mode (default)
To use the same script everywhere, use the convenience function `DecompilerInterface.discover_interface()`, which will
auto find the correct interface. Copy the below code into any supported decompiler and it should run without edit.

```python
from libbs.api import DecompilerInterface

deci = DecompilerInterface.discover()
for addr in deci.functions:
    function = deci.functions[addr]
    if function.header.type == "void":
        function.header.type = "int"
        deci.functions[function.addr] = function
```

### Headless Mode 
To use headless mode you must specify a decompiler to use. You can get the traditional interface using the following:

```python 
from libbs.api import DecompilerInterface

deci = DecompilerInterface.discover(force_decompiler="ghidra", headless=True)
```

In the case of decompilers that don't have a native python library for working with, like Ghidra and IDA, you will to 
tell libbs where the headless binary path exists. This can be passed through either `headless_dec_path` flag, or
through your environment. For Ghidra this would be: `GHIDRA_HEADLESS_PATH`.


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

### Serializing Artifacts
All artifacts are serializable to the TOML and JSON formats. Serialization is done like so:
```python
from libbs.artifacts import Function
import json

my_func = Function(name="my_func", addr=0x4000, size=0x10)
json_str = my_func.dumps(fmt="json")
loaded_dict = json.loads(json_str) # now loadable through normal JSON parsing
loaded_func = Function.loads(json_str, fmt="json")
```
