from platformdirs import user_config_dir
import pathlib
import toml

# Use binsync Config obj as base
class LibbsConfig():
    __slots__ = (
        "path",
        "plugin_path",
        "headless_binary_path",
        "last_project",
        "plugin_data",
    )

    def __init__(self, plugin_path, headless_binary_path=None):
        self.path = pathlib.Path(user_config_dir("libbs")) / "libbs.toml"
        # TODO: Figure out plugin_path
        self.plugin_path = plugin_path
        # TODO: Attempt to infer binary path from installation data
        self.headless_binary_path = pathlib.Path(headless_binary_path) if headless_binary_path else None
        self.last_project = None
        # self.data will be a dict of dicts keyed by plugin_name
        # each dict in self.data contains what a particular plugin wants stored in the config file
        self.plugin_data = {}

    def save(self):
        if not self.path.parent.exists():
            self.path.parent.mkdir()

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

        self.path = pathlib.Path(self.path)
        self.headless_binary_path = pathlib.Path(self.headless_binary_path) if self.headless_binary_path else None

        return self

