try:
    import angrmanagement
    AM_PRESENT = True
except ImportError:
    AM_PRESENT = False

if AM_PRESENT:
    try:
        from .plugin import *
    except ImportError:
        pass
