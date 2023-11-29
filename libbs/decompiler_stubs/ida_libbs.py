def PLUGIN_ENTRY(*args, **kwargs):
    try:
        from libbs.decompilers.ida import LibBSPlugin
    except ImportError:
        print("[!] libbs is not installed, please `pip install libbs` for THIS python interpreter")
        return None

    return LibBSPlugin(*args, **kwargs)
