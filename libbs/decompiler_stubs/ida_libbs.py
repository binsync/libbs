def PLUGIN_ENTRY(*args, **kwargs):
    try:
        from libbs.decompilers.ida import libbsPlugin
    except ImportError:
        print("[!] libbs is not installed, please `pip install libbs` for THIS python interpreter")
        return None

    return libbsPlugin(*args, **kwargs)
