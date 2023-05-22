def PLUGIN_ENTRY(*args, **kwargs):
    try:
        from yodalib.decompilers.ida import YODALibPlugin
    except ImportError:
        print("[!] yodalib is not installed, please `pip install yodalib` for THIS python interpreter")
        return None

    return YODALibPlugin(*args, **kwargs)
