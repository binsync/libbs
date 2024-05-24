from typing import Optional

from .artifact import Artifact
from .func import Function


class Context(Artifact):
    __slots__ = Artifact.__slots__ + (
        "addr",
        "func_addr",
        "screen_name"
    )

    def __init__(self, addr: int = None, func: Optional[Function] = None, screen_name: str = None, **kwargs):
        super().__init__(**kwargs)
        self.addr = addr
        self.func_addr = func
        self.screen_name = screen_name

    def __str__(self):
        post_text = f" name={self.screen_name}" if self.screen_name else ""
        if self.func_addr is not None:
            post_text = f"@{hex(self.func_addr)}" + post_text
            if self.addr is not None:
                post_text = hex(self.addr) + post_text

        return f"<Context {post_text}>"
