from libbs.decompilers import SUPPORTED_DECOMPILERS
from platformdirs import user_config_dir
import pathlib
import logging
import toml

_l = logging.getLogger(__name__)

# TODO: Add file locking to prevent simultaneous file accessing
class BSConfig:
    __slots__ = (
        "save_location"
    )

    def __init__(self, save_location=None):
        if not save_location:
            save_location = user_config_dir("libbs")
        self.save_location = _create_path(save_location) / f"{__class__.__name__}.toml"

    def save(self):
        if not self.save_location.parent.exists():
            self.save_location.parent.mkdir()

        dump_dict = {}
        for attr in self.__slots__:
            attr_val = getattr(self, attr)
            if isinstance(attr_val, pathlib.Path):
                attr_val = str(attr_val)

            dump_dict[attr] = attr_val

        with open(self.save_location, "w") as fp:
            toml.dump(dump_dict, fp)

    def load(self):
        self.save_location = _create_path(self.save_location)
        if not self.save_location.exists():
            return None

        with open(self.save_location, "r") as fp:
            load_dict = toml.load(fp)

        for attr in self.__slots__:
            setattr(self, attr, load_dict.get(attr, None))

        return self

    @classmethod
    def load_from_file(cls, save_location):
        config = cls(save_location)
        return config.load()

    @classmethod
    def update_or_make(cls, save_location, **attrs_to_update):
        save_location = _create_path(save_location) if save_location else None
        config = cls.load_from_file(save_location) if save_location.exists() else cls(save_location)

        for attr, val in attrs_to_update.items():
            if attr in config.__slots__:
                setattr(config, attr, val)

        config.save()
        return config


class LibbsConfig(BSConfig):
    __slots__ = (
        "save_location",
        "plugins_paths",
        "headless_binary_paths",
        "gdbinit_path",
    )

    def __init__(self, save_location, plugins_paths=None, headless_binary_paths=None, gdbinit_path=None):
        super(BSConfig, self).__init__(save_location)
        self.gdbinit_path = gdbinit_path
        for decompiler in SUPPORTED_DECOMPILERS:
            plugins_path = plugins_paths[decompiler] if decompiler in plugins_paths else None
            headless_path = headless_binary_paths[decompiler] if decompiler in headless_binary_paths else None
            # Check if only one is set and infer the other path
            if plugins_path and not headless_path:
                headless_path = _infer_headless_path(plugins_path)
            elif headless_path and not plugins_path:
                plugins_path = _infer_plugins_path(headless_path)
            self.plugins_paths[decompiler] = plugins_path
            self.headless_binary_paths[decompiler] = headless_path


def _create_path(path_str):
    return pathlib.Path(path_str).expanduser().absolute()
def _infer_headless_path(plugin_path):
    plugin_path = _create_path(plugin_path)
    # TODO: Implement me
    return None

def _infer_plugins_path(headless_path):
    headless_path = _create_path(headless_path)
    # TODO: Implement me
    return None