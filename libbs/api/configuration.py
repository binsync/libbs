from platformdirs import user_config_dir
import pathlib
import toml

# Use binsync Config obj as base
class LibbsConfig():
    __slots__ = (
        "plugin_path",
        "headless_binary_path",
        "last_project",
        "plugin_data",
    )

    def __init__(self, plugin_path, headless_binary_path=None):
        self.path = user_config_dir("libbs")+"/libbs.toml"
        self.plugin_path = plugin_path
        if not headless_binary_path:
            # Attempt to locate automatically from install location
            pass
        self.headless_binary_path = headless_binary_path
        self.last_project = None
        # self.data will be a dict of dicts keyed by plugin_name
        # each dict in self.data contains what a particular plugin wants stored in the config file
        self.plugin_data = {}

    def save(self):
        self.path = pathlib.Path(self.path)
        if not self.path.parent.exists():
            return None

        dump_dict = {}
        for attr in self.__slots__:
            attr_val = getattr(self, attr)
            if isinstance(attr_val, pathlib.Path):
                attr_val = str(attr_val)

            dump_dict[attr] = attr_val

        with open(self.path, "w") as fp:
            toml.dump(dump_dict, fp)

    def load(self):
        self.path = pathlib.Path(self.path)
        if not self.path.exists():
            return None

        with open(self.path, "r") as fp:
            load_dict = toml.load(fp)

        for attr in self.__slots__:
            setattr(self, attr, load_dict.get(attr, None))

        return self

