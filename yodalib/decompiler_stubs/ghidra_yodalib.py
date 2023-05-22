try:
    from yodalib.decompilers.ghidra.server import start
except ImportError:
    print("[!] yodalib is not installed, please `pip install yodalib` for THIS python interpreter")
