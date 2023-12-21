from libbs.api import DecompilerInterface

deci = DecompilerInterface.discover_interface()
for function in deci.functions:
    if function.header.type == "void *":
        function.header.type = "long long"

    deci.functions[function.addr] = function
